package cluster

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	bank        = "sha256"
	digestBytes = 32
)

var pcrSelection = []int{0, 1, 2, 3, 7, 11}

func pcrList() string {
	parts := make([]string, len(pcrSelection))
	for index, number := range pcrSelection {
		parts[index] = strconv.Itoa(number)
	}
	return bank + ":" + strings.Join(parts, ",")
}

func runTool(environment []string, name string, arguments ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, arguments...)
	if environment != nil {
		command.Env = append(os.Environ(), environment...)
	}
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if len(message) > 300 {
			message = message[len(message)-300:]
		}
		return nil, attestationError("%s: %s", name, message)
	}
	return stdout.Bytes(), nil
}

var tpmSequence sync.Mutex

type TPMProver struct{ Environment []string }

func (prover *TPMProver) tool(name string, arguments ...string) ([]byte, error) {
	return runTool(prover.Environment, name, arguments...)
}

func (prover *TPMProver) flush() {
	for _, option := range []string{"-t", "-l", "-s"} {
		_, _ = prover.tool("tpm2_flushcontext", option)
	}
}

const akAttributes = "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign|noda"

func ekContext(work string) string { return filepath.Join(work, "ek.ctx") }
func akContext(work string) string { return filepath.Join(work, "ak.ctx") }

func (prover *TPMProver) prepare(work string) error {
	prover.flush()
	if _, err := prover.tool("tpm2_createek", "-c", ekContext(work), "-G", "ecc", "-u", filepath.Join(work, "ek.pub")); err != nil {
		return err
	}
	_, err := prover.tool("tpm2_createprimary", "-C", "o", "-c", akContext(work), "-G", "ecc256:ecdsa-sha256:null", "-g", bank, "-a", akAttributes)
	return err
}

func workDir() (string, func()) {
	directory, err := os.MkdirTemp("", "fistpumpd-tpm-")
	if err != nil {
		panic(err)
	}
	return directory, func() { _ = os.RemoveAll(directory) }
}

func (prover *TPMProver) Hello() (Obj, error) {
	tpmSequence.Lock()
	defer tpmSequence.Unlock()
	work, cleanup := workDir()
	defer cleanup()
	if err := prover.prepare(work); err != nil {
		return nil, err
	}
	if _, err := prover.tool("tpm2_readpublic", "-c", akContext(work), "-o", filepath.Join(work, "ak.pub"), "-n", filepath.Join(work, "ak.name")); err != nil {
		return nil, err
	}
	ek, _ := os.ReadFile(filepath.Join(work, "ek.pub"))
	ak, _ := os.ReadFile(filepath.Join(work, "ak.pub"))
	name, _ := os.ReadFile(filepath.Join(work, "ak.name"))
	return Obj{
		"ek_pub":  base64.StdEncoding.EncodeToString(ek),
		"ak_pub":  base64.StdEncoding.EncodeToString(ak),
		"ak_name": hex.EncodeToString(name),
	}, nil
}

func (prover *TPMProver) Answer(challenge string) (string, error) {
	tpmSequence.Lock()
	defer tpmSequence.Unlock()
	work, cleanup := workDir()
	defer cleanup()
	if err := prover.prepare(work); err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil {
		return "", attestationError("bad challenge")
	}
	if err := os.WriteFile(filepath.Join(work, "cred.blob"), raw, 0o600); err != nil {
		return "", err
	}
	session := filepath.Join(work, "session.ctx")
	if _, err := prover.tool("tpm2_startauthsession", "--policy-session", "-S", session); err != nil {
		return "", err
	}
	defer func() { _, _ = prover.tool("tpm2_flushcontext", session) }()
	if _, err := prover.tool("tpm2_policysecret", "-S", session, "-c", "e"); err != nil {
		return "", err
	}
	if _, err := prover.tool("tpm2_activatecredential", "-c", akContext(work), "-C", ekContext(work), "-i", filepath.Join(work, "cred.blob"),
		"-o", filepath.Join(work, "secret.out"), "-P", "session:"+session); err != nil {
		return "", err
	}
	secret, err := os.ReadFile(filepath.Join(work, "secret.out"))
	return hex.EncodeToString(secret), err
}

func (prover *TPMProver) Quote(nonce, signPub, tlsFP string) (Obj, error) {
	qualifying, err := Binding(nonce, signPub, tlsFP)
	if err != nil {
		return nil, err
	}
	return prover.QuoteQualifying(qualifying)
}

func (prover *TPMProver) QuoteQualifying(qualifying string) (Obj, error) {
	tpmSequence.Lock()
	defer tpmSequence.Unlock()
	work, cleanup := workDir()
	defer cleanup()
	if err := prover.prepare(work); err != nil {
		return nil, err
	}
	before, after := filepath.Join(work, "before.pcrs"), filepath.Join(work, "quote.pcrs")
	stable := false
	for attempt := 0; attempt < 3 && !stable; attempt++ {
		if _, err := prover.tool("tpm2_pcrread", pcrList(), "-o", before); err != nil {
			return nil, err
		}
		if _, err := prover.tool("tpm2_quote", "-c", akContext(work), "-l", pcrList(), "-q", qualifying, "-m", filepath.Join(work, "quote.msg"),
			"-s", filepath.Join(work, "quote.sig"), "-g", bank); err != nil {
			return nil, err
		}
		if _, err := prover.tool("tpm2_pcrread", pcrList(), "-o", after); err != nil {
			return nil, err
		}
		first, _ := os.ReadFile(before)
		second, _ := os.ReadFile(after)
		stable = bytes.Equal(first, second)
	}
	if !stable {
		return nil, attestationError("the PCRs keep changing")
	}
	raw, _ := os.ReadFile(after)
	if len(raw) != digestBytes*len(pcrSelection) {
		return nil, attestationError("unexpected PCR data length")
	}
	pcrs := Obj{}
	for index, number := range pcrSelection {
		pcrs[strconv.Itoa(number)] = hex.EncodeToString(raw[index*digestBytes : (index+1)*digestBytes])
	}
	message, _ := os.ReadFile(filepath.Join(work, "quote.msg"))
	signature, _ := os.ReadFile(filepath.Join(work, "quote.sig"))
	return Obj{
		"pcrs":      pcrs,
		"message":   base64.StdEncoding.EncodeToString(message),
		"signature": base64.StdEncoding.EncodeToString(signature),
	}, nil
}

type TPMVerifier struct{}

func (TPMVerifier) Challenge(hello Obj) (string, string, error) {
	secret := make([]byte, digestBytes)
	if _, err := rand.Read(secret); err != nil {
		return "", "", err
	}
	ek, err := base64.StdEncoding.DecodeString(str(hello, "ek_pub"))
	if err != nil {
		return "", "", attestationError("bad endorsement key")
	}
	key, err := helloKey(hello)
	if err != nil {
		return "", "", err
	}
	work, cleanup := workDir()
	defer cleanup()
	_ = os.WriteFile(filepath.Join(work, "ek.pub"), ek, 0o600)
	_ = os.WriteFile(filepath.Join(work, "secret"), secret, 0o600)
	if _, err := runTool(nil, "tpm2_makecredential", "-T", "none", "-e", filepath.Join(work, "ek.pub"), "-s", filepath.Join(work, "secret"),
		"-n", hex.EncodeToString(key.name), "-o", filepath.Join(work, "cred.blob")); err != nil {
		return "", "", err
	}
	blob, err := os.ReadFile(filepath.Join(work, "cred.blob"))
	if err != nil {
		return "", "", attestationError("no credential was made")
	}
	return base64.StdEncoding.EncodeToString(blob), hex.EncodeToString(secret), nil
}

func helloKey(hello Obj) (*attestationKey, error) {
	raw, err := base64.StdEncoding.DecodeString(str(hello, "ak_pub"))
	if err != nil {
		return nil, attestationError("bad attestation key")
	}
	return parseAttestationKey(raw)
}

func (TPMVerifier) CheckQuote(hello, quote Obj, qualifying string) (map[string]string, error) {
	key, err := helloKey(hello)
	if err != nil {
		return nil, err
	}
	given, _ := quote["pcrs"].(Obj)
	var raw []byte
	values := map[string]string{}
	for _, number := range pcrSelection {
		name := strconv.Itoa(number)
		value, _ := given[name].(string)
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != digestBytes {
			return nil, attestationError("the quote lacks some of the PCRs")
		}
		raw = append(raw, decoded...)
		values[name] = strings.ToLower(value)
	}
	message, messageErr := base64.StdEncoding.DecodeString(str(quote, "message"))
	signature, signatureErr := base64.StdEncoding.DecodeString(str(quote, "signature"))
	expected, expectedErr := hex.DecodeString(qualifying)
	if messageErr != nil || signatureErr != nil || expectedErr != nil {
		return nil, attestationError("the quote is not encoded as expected")
	}
	if err := verifyQuoteSignature(key.public, message, signature); err != nil {
		return nil, err
	}
	if err := verifyQuoteMessage(message, expected, raw); err != nil {
		return nil, err
	}
	return values, nil
}
