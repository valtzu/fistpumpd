package cluster

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

type AttestationError struct{ Message string }

func (e *AttestationError) Error() string { return e.Message }

func attestationError(format string, args ...any) error {
	return &AttestationError{Message: fmt.Sprintf(format, args...)}
}

type Prover interface {
	Hello() (Obj, error)
	Answer(challenge string) (string, error)
	Quote(nonce, signPub, tlsFP string) (Obj, error)
}

type Verifier interface {
	Challenge(hello Obj) (blob string, secret string, err error)
	CheckQuote(hello, quote Obj, qualifying string) (map[string]string, error)
}

func Binding(nonce, signPub, tlsFP string) (string, error) {
	var joined []byte
	for _, part := range []string{nonce, signPub, tlsFP} {
		raw, err := hex.DecodeString(part)
		if err != nil {
			return "", attestationError("binding input is not hex")
		}
		joined = append(joined, raw...)
	}
	sum := sha256.Sum256(joined)
	return hex.EncodeToString(sum[:]), nil
}

const nonceBytes = 20

func NewNonce() string {
	raw := make([]byte, nonceBytes)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	return hex.EncodeToString(raw)
}

func EKHash(hello Obj) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(str(hello, "ek_pub"))
	if err != nil {
		return "", attestationError("the endorsement key is not base64")
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func Attest(prover Prover, verifier Verifier, expectedEK, nonce, signPub, tlsFP string) (map[string]string, error) {
	hello, err := prover.Hello()
	if err != nil {
		return nil, err
	}
	hash, err := EKHash(hello)
	if err != nil {
		return nil, err
	}
	if hash != expectedEK {
		return nil, attestationError("the endorsement key is not the one in the join request")
	}
	blob, secret, err := verifier.Challenge(hello)
	if err != nil {
		return nil, err
	}
	answer, err := prover.Answer(blob)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(answer), []byte(secret)) != 1 {
		return nil, attestationError("the attestation key is not bound to the endorsement key")
	}
	qualifying, err := Binding(nonce, signPub, tlsFP)
	if err != nil {
		return nil, err
	}
	quote, err := prover.Quote(nonce, signPub, tlsFP)
	if err != nil {
		return nil, err
	}
	return verifier.CheckQuote(hello, quote, qualifying)
}

type RemoteProver struct {
	Call func(method string, payload Obj) (Obj, error)
}

func (remote RemoteProver) Hello() (Obj, error) { return remote.Call("attest_hello", Obj{}) }

func (remote RemoteProver) Answer(challenge string) (string, error) {
	reply, err := remote.Call("attest_answer", Obj{"challenge": challenge})
	if err != nil {
		return "", err
	}
	return str(reply, "secret"), nil
}

func (remote RemoteProver) Quote(nonce, signPub, tlsFP string) (Obj, error) {
	payload := Obj{"nonce": nonce}
	if legacy, err := Binding(nonce, signPub, tlsFP); err == nil {
		payload["qualifying"] = legacy
	}
	return remote.Call("attest_quote", payload)
}

type legacyProver interface {
	QuoteQualifying(qualifying string) (Obj, error)
}

func legacyQuote(prover Prover, qualifying string) (Obj, error) {
	legacy, supported := prover.(legacyProver)
	if raw, err := hex.DecodeString(qualifying); !supported || err != nil || len(raw) != sha256.Size {
		return nil, attestationError("a quote is asked for with a nonce of %d bytes", nonceBytes)
	}
	return legacy.QuoteQualifying(qualifying)
}

func ServeAttestation(prover Prover, record Obj, acceptLegacy bool, method string, payload Obj) (Obj, bool, error) {
	switch method {
	case "attest_hello":
		reply, err := prover.Hello()
		return reply, true, err
	case "attest_answer":
		secret, err := prover.Answer(str(payload, "challenge"))
		return Obj{"secret": secret}, true, err
	case "attest_quote":
		nonce, hasNonce := payload["nonce"].(string)
		if !hasNonce && acceptLegacy {
			reply, err := legacyQuote(prover, str(payload, "qualifying"))
			return reply, true, err
		}
		if raw, err := hex.DecodeString(nonce); err != nil || len(raw) != nonceBytes {
			return nil, true, attestationError("a quote is asked for with a nonce of %d bytes", nonceBytes)
		}
		reply, err := prover.Quote(nonce, str(record, "sign_pub"), str(record, "tls_fp"))
		return reply, true, err
	}
	return nil, false, nil
}

func isAttestation(err error) bool {
	var target *AttestationError
	return errors.As(err, &target)
}
