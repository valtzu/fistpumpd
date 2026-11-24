package cluster

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	stdstrings "strings"
	"time"
)

var policySections = []string{"firmware", "peripheral_firmware", "eeprom_configuration", "versions"}

type Opener func(url string) ([]byte, error)

func HTTPOpener(url string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	response, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("%s: HTTP %d", url, response.StatusCode)
	}
	return io.ReadAll(io.LimitReader(response.Body, 16<<20))
}

func verifySignature(sums, signature []byte, keyring string) error {
	work, err := os.MkdirTemp("", "rpi-cluster-gpg-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	_ = os.WriteFile(filepath.Join(work, "sums"), sums, 0o600)
	_ = os.WriteFile(filepath.Join(work, "sums.gpg"), signature, 0o600)
	command := exec.Command("gpg", "--batch", "--no-default-keyring", "--keyring", keyring, "--trust-model", "always",
		"--verify", filepath.Join(work, "sums.gpg"), filepath.Join(work, "sums"))
	command.Env = append(os.Environ(), "GNUPGHOME="+work)
	if err := command.Run(); err != nil {
		return fmt.Errorf("SHA256SUMS is not signed by the update key")
	}
	return nil
}

func checksumOf(sums []byte, name string) (string, error) {
	for _, line := range stdstrings.Split(string(sums), "\n") {
		digest, rest, found := stdstrings.Cut(stdstrings.TrimSpace(line), " ")
		if found && stdstrings.TrimPrefix(stdstrings.TrimSpace(rest), "*") == name {
			return digest, nil
		}
	}
	return "", fmt.Errorf("SHA256SUMS does not list %s", name)
}

func FetchPolicy(base, keyring string, open Opener) (Obj, error) {
	base = stdstrings.TrimRight(base, "/")
	sums, err := open(base + "/SHA256SUMS")
	if err != nil {
		return nil, err
	}
	signature, err := open(base + "/SHA256SUMS.gpg")
	if err != nil {
		return nil, err
	}
	if err := verifySignature(sums, signature, keyring); err != nil {
		return nil, err
	}
	document, err := open(base + "/versions.json")
	if err != nil {
		return nil, err
	}
	want, err := checksumOf(sums, "versions.json")
	if err != nil {
		return nil, err
	}
	got := sha256.Sum256(document)
	if hex.EncodeToString(got[:]) != want {
		return nil, fmt.Errorf("%s/versions.json does not match its signed checksum", base)
	}
	return DecodeObj(document)
}

func equalJSON(a, b any) bool { return bytes.Equal(Marshal(a), Marshal(b)) }

func MergePolicies(documents []Obj) Obj {
	merged := Obj{}
	for _, section := range policySections {
		merged[section] = []any{}
	}
	boots := []any{}
	for _, document := range documents {
		for _, section := range policySections {
			list, _ := document[section].([]any)
			for _, entry := range list {
				present := false
				for _, existing := range merged[section].([]any) {
					present = present || equalJSON(existing, entry)
				}
				if !present {
					merged[section] = append(merged[section].([]any), entry)
				}
			}
		}
		if boot, ok := document["secure_boot"].(Obj); ok && len(boot) > 0 {
			present := false
			for _, existing := range boots {
				present = present || equalJSON(existing, boot)
			}
			if !present {
				boots = append(boots, boot)
			}
		}
	}
	merged["secure_boot_all"] = boots
	return merged
}

func RefreshPolicy(urls []string, keyring, cache string, open Opener) (Obj, error) {
	var documents []Obj
	var failures []string
	for _, url := range urls {
		document, err := FetchPolicy(url, keyring, open)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		documents = append(documents, document)
	}
	if len(documents) > 0 {
		merged := MergePolicies(documents)
		if err := os.MkdirAll(filepath.Dir(cache), 0o755); err == nil {
			_ = writeAtomic(cache, Marshal(merged), 0o644)
		}
		return merged, nil
	}
	if data, err := os.ReadFile(cache); err == nil {
		return DecodeObj(data)
	}
	if len(failures) == 0 {
		failures = []string{"no policy source"}
	}
	return nil, fmt.Errorf("%s", stdstrings.Join(failures, "; "))
}
