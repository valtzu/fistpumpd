package cluster

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	stdstrings "strings"
)

const DefaultCredstore = "/var/lib/credstore.encrypted"

var tokenKinds = []string{"server", "agent"}
var credentialNames = map[string]string{"server": "k3s.token", "agent": "k3s-agent.token"}

type Tokens struct {
	Directory string
	Credstore string
	Seal      bool
}

func NewTokens(directory, credstore string, seal bool) (*Tokens, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	return &Tokens{Directory: directory, Credstore: credstore, Seal: seal && sealingAvailable()}, nil
}

func (tokens *Tokens) path(kind string) string { return filepath.Join(tokens.Directory, kind+".token") }

func (tokens *Tokens) Get(kind string) string {
	data, err := os.ReadFile(tokens.path(kind))
	if err != nil {
		return ""
	}
	return stdstrings.TrimSpace(string(data))
}

func (tokens *Tokens) Put(kind, value string) error {
	return writeAtomic(tokens.path(kind), []byte(value+"\n"), 0o600)
}

func (tokens *Tokens) Create() error {
	for _, kind := range tokenKinds {
		if tokens.Get(kind) != "" {
			continue
		}
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		if err := tokens.Put(kind, hex.EncodeToString(raw)); err != nil {
			return err
		}
	}
	return nil
}

func (tokens *Tokens) InstallCredentials(kinds []string) error {
	if err := os.MkdirAll(tokens.Credstore, 0o700); err != nil {
		return err
	}
	for _, kind := range kinds {
		value := tokens.Get(kind)
		if value == "" {
			continue
		}
		target := filepath.Join(tokens.Credstore, credentialNames[kind])
		if tokens.Seal {
			command := exec.Command("systemd-creds", "encrypt", "--with-key=tpm2", "--tpm2-pcrs=7", "--name="+credentialNames[kind], "-", target)
			command.Stdin = bytes.NewReader([]byte(value))
			if output, err := command.CombinedOutput(); err != nil {
				return fmt.Errorf("systemd-creds: %s", stdstrings.TrimSpace(string(output)))
			}
			continue
		}
		if err := writeAtomic(target, []byte(value+"\n"), 0o600); err != nil {
			return err
		}
	}
	return nil
}
