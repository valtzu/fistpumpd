package cluster

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func sealingAvailable() bool {
	if os.Getenv("RPI_CLUSTER_NO_SEAL") != "" {
		return false
	}
	_, err := os.Stat("/dev/tpmrm0")
	return err == nil
}

func sealTo(plain []byte, target, name string) bool {
	if !sealingAvailable() {
		return false
	}
	command := exec.Command("systemd-creds", "encrypt", "--with-key=tpm2", "--tpm2-pcrs=7", "--name="+name, "-", target)
	command.Stdin = bytes.NewReader(plain)
	return command.Run() == nil
}

func unseal(source, name string) ([]byte, error) {
	return exec.Command("systemd-creds", "decrypt", "--name="+name, source, "-").Output()
}

func LoadKey(directory string) (ed25519.PrivateKey, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	sealed, plain := filepath.Join(directory, "sign.key.cred"), filepath.Join(directory, "sign.key")
	if _, err := os.Stat(sealed); err == nil {
		seed, err := unseal(sealed, "rpi-cluster")
		if err != nil {
			return nil, err
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	if seed, err := os.ReadFile(plain); err == nil {
		return ed25519.NewKeyFromSeed(seed), nil
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if !sealTo(seed, sealed, "rpi-cluster") {
		if err := os.WriteFile(plain, seed, 0o600); err != nil {
			return nil, err
		}
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func PublicHex(key ed25519.PrivateKey) string {
	return hex.EncodeToString(key.Public().(ed25519.PublicKey))
}

func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func CreateTLS(directory string) (keyPath, certPath, fingerprint string, err error) {
	if err = os.MkdirAll(directory, 0o700); err != nil {
		return
	}
	keyPath, certPath = filepath.Join(directory, "tls.key"), filepath.Join(directory, "tls.crt")
	_, keyErr := os.Stat(keyPath)
	_, certErr := os.Stat(certPath)
	if keyErr != nil || certErr != nil {
		key, genErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if genErr != nil {
			err = genErr
			return
		}
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
		template := &x509.Certificate{
			SerialNumber: serial, Subject: pkix.Name{CommonName: "rpi-cluster-member"},
			NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(3650 * 24 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, createErr := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if createErr != nil {
			err = createErr
			return
		}
		encoded, _ := x509.MarshalPKCS8PrivateKey(key)
		if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0o600); err != nil {
			return
		}
		if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
			return
		}
	}
	data, readErr := os.ReadFile(certPath)
	if readErr != nil {
		err = readErr
		return
	}
	block, _ := pem.Decode(data)
	if block == nil {
		err = os.ErrInvalid
		return
	}
	fingerprint = Fingerprint(block.Bytes)
	return
}
