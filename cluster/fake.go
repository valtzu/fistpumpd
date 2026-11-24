package cluster

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"sort"
)

type FakeTPM struct {
	PCRs map[string]string
	ek   []byte
	ak   []byte
}

func NewFakeTPM(pcrs map[string]string) *FakeTPM {
	key := make([]byte, 32)
	ek := make([]byte, 32)
	_, _ = rand.Read(key)
	_, _ = rand.Read(ek)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("ak"))
	return &FakeTPM{PCRs: pcrs, ek: ek, ak: mac.Sum(nil)}
}

func (fake *FakeTPM) Hello() (Obj, error) {
	name := sha256.Sum256(fake.ak)
	return Obj{
		"ek_pub":  base64.StdEncoding.EncodeToString(fake.ek),
		"ak_pub":  base64.StdEncoding.EncodeToString(fake.ak),
		"ak_name": hex.EncodeToString(name[:]),
	}, nil
}

func hmacHex(key, message []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return hex.EncodeToString(mac.Sum(nil))
}

func (fake *FakeTPM) Answer(challenge string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil {
		return "", attestationError("bad challenge")
	}
	return hmacHex(fake.ek, raw), nil
}

func fakeMessage(pcrs map[string]string, qualifying string) string {
	keys := make([]string, 0, len(pcrs))
	for key := range pcrs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	message := ""
	for _, key := range keys {
		message += key + "=" + pcrs[key] + ";"
	}
	return message + qualifying
}

func (fake *FakeTPM) Quote(qualifying string) (Obj, error) {
	pcrs := Obj{}
	selected := map[string]string{}
	for _, number := range []string{"0", "1", "2", "3", "7", "11"} {
		if value, ok := fake.PCRs[number]; ok {
			pcrs[number] = value
			selected[number] = value
		}
	}
	message := fakeMessage(selected, qualifying)
	return Obj{"pcrs": pcrs, "message": message, "signature": hmacHex(fake.ak, []byte(message))}, nil
}

type FakeVerifier struct{}

func (FakeVerifier) Challenge(hello Obj) (string, string, error) {
	blob := make([]byte, 16)
	_, _ = rand.Read(blob)
	ek, err := base64.StdEncoding.DecodeString(str(hello, "ek_pub"))
	if err != nil {
		return "", "", attestationError("bad endorsement key")
	}
	return base64.StdEncoding.EncodeToString(blob), hmacHex(ek, blob), nil
}

func (FakeVerifier) CheckQuote(hello, quote Obj, qualifying string) (map[string]string, error) {
	ak, err := base64.StdEncoding.DecodeString(str(hello, "ak_pub"))
	if err != nil {
		return nil, attestationError("bad attestation key")
	}
	pcrs := map[string]string{}
	given, _ := quote["pcrs"].(Obj)
	for key, value := range given {
		pcrs[key], _ = value.(string)
	}
	message := fakeMessage(pcrs, qualifying)
	expected := hmacHex(ak, []byte(message))
	if str(quote, "message") != message || !hmac.Equal([]byte(expected), []byte(str(quote, "signature"))) {
		return nil, attestationError("quote signature does not match the attestation key")
	}
	return pcrs, nil
}
