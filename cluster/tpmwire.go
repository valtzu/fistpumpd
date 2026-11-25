package cluster

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

const (
	tpmAlgSHA256    = 0x000b
	tpmAlgNull      = 0x0010
	tpmAlgECDSA     = 0x0018
	tpmAlgECC       = 0x0023
	tpmCurveP256    = 0x0003
	tpmGenerated    = 0xff544347
	tpmAttestQuote  = 0x8018
	tpmClockInfo    = 17
	tpmFirmwareSize = 8

	attributeFixedTPM            = 1 << 1
	attributeFixedParent         = 1 << 4
	attributeSensitiveDataOrigin = 1 << 5
	attributeRestricted          = 1 << 16
	attributeDecrypt             = 1 << 17
	attributeSign                = 1 << 18

	attestationKeyRequired = attributeFixedTPM | attributeFixedParent | attributeSensitiveDataOrigin | attributeRestricted | attributeSign
)

type wire struct {
	data   []byte
	failed bool
}

func (w *wire) take(count int) []byte {
	if w.failed || count < 0 || count > len(w.data) {
		w.failed = true
		return nil
	}
	taken := w.data[:count]
	w.data = w.data[count:]
	return taken
}

func (w *wire) u8() int {
	if raw := w.take(1); raw != nil {
		return int(raw[0])
	}
	return 0
}

func (w *wire) u16() int {
	if raw := w.take(2); raw != nil {
		return int(binary.BigEndian.Uint16(raw))
	}
	return 0
}

func (w *wire) u32() uint32 {
	if raw := w.take(4); raw != nil {
		return binary.BigEndian.Uint32(raw)
	}
	return 0
}

func (w *wire) sized() []byte { return w.take(w.u16()) }

func (w *wire) done() bool { return !w.failed && len(w.data) == 0 }

type attestationKey struct {
	public *ecdsa.PublicKey
	name   []byte
}

func parseAttestationKey(raw []byte) (*attestationKey, error) {
	outer := wire{data: raw}
	area := outer.sized()
	if !outer.done() {
		return nil, attestationError("the attestation key is not a TPM public area")
	}
	fields := wire{data: area}
	kind, nameAlg, attributes := fields.u16(), fields.u16(), fields.u32()
	fields.sized()
	symmetric, scheme, schemeHash, curve, kdf := fields.u16(), fields.u16(), fields.u16(), fields.u16(), fields.u16()
	x, y := fields.sized(), fields.sized()
	if !fields.done() || kind != tpmAlgECC || nameAlg != tpmAlgSHA256 || symmetric != tpmAlgNull ||
		scheme != tpmAlgECDSA || schemeHash != tpmAlgSHA256 || curve != tpmCurveP256 || kdf != tpmAlgNull {
		return nil, attestationError("the attestation key is not an ECDSA P-256 SHA-256 key")
	}
	if attributes&attestationKeyRequired != attestationKeyRequired || attributes&attributeDecrypt != 0 {
		return nil, attestationError("the attestation key is not a restricted signing key that the TPM made")
	}
	public := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if _, err := public.ECDH(); err != nil {
		return nil, attestationError("the attestation key is not a point on the curve")
	}
	digest := sha256.Sum256(area)
	return &attestationKey{public: public, name: append([]byte{0, tpmAlgSHA256}, digest[:]...)}, nil
}

func verifyQuoteSignature(key *ecdsa.PublicKey, message, signature []byte) error {
	fields := wire{data: signature}
	algorithm, hash := fields.u16(), fields.u16()
	r, s := fields.sized(), fields.sized()
	if !fields.done() || algorithm != tpmAlgECDSA || hash != tpmAlgSHA256 {
		return attestationError("the quote signature is not ECDSA with SHA-256")
	}
	digest := sha256.Sum256(message)
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(r), new(big.Int).SetBytes(s)) {
		return attestationError("the quote signature does not match the attestation key")
	}
	return nil
}

func selectedPCRs(bitmap []byte) []int {
	var selected []int
	for index, octet := range bitmap {
		for bit := 0; bit < 8; bit++ {
			if octet&(1<<bit) != 0 {
				selected = append(selected, index*8+bit)
			}
		}
	}
	return selected
}

func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func verifyQuoteMessage(message, qualifying, pcrValues []byte) error {
	fields := wire{data: message}
	magic, kind := fields.u32(), fields.u16()
	fields.sized()
	extra := fields.sized()
	fields.take(tpmClockInfo + tpmFirmwareSize)
	selections, bank := fields.u32(), fields.u16()
	bitmap := fields.take(fields.u8())
	digest := fields.sized()
	if !fields.done() || magic != tpmGenerated || kind != tpmAttestQuote {
		return attestationError("the quote is not a quote structure that a TPM made")
	}
	if !bytes.Equal(extra, qualifying) {
		return attestationError("the quote does not carry the nonce and the keys of this node")
	}
	if selections != 1 || bank != tpmAlgSHA256 || !sameInts(selectedPCRs(bitmap), pcrSelection) {
		return attestationError("the quote covers another PCR selection")
	}
	expected := sha256.Sum256(pcrValues)
	if !bytes.Equal(digest, expected[:]) {
		return attestationError("the quote does not cover the reported PCR values")
	}
	return nil
}
