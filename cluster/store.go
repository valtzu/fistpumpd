package cluster

import (
	"os"
	"path/filepath"
	"sync"
)

type Store interface {
	Append(line string) error
	LoadLines() ([]string, error)
	SaveVotes(votes Obj) error
	LoadVotes() Obj
}

type MemoryStore struct {
	mutex sync.Mutex
	lines []string
	votes []byte
}

func (store *MemoryStore) Append(line string) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.lines = append(store.lines, line)
	return nil
}

func (store *MemoryStore) LoadLines() ([]string, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	return append([]string(nil), store.lines...), nil
}

func (store *MemoryStore) SaveVotes(votes Obj) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.votes = Marshal(votes)
	return nil
}

func (store *MemoryStore) LoadVotes() Obj {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.votes == nil {
		return Obj{}
	}
	votes, _ := DecodeObj(store.votes)
	return votes
}

type DirStore struct{ Directory string }

func NewDirStore(directory string) (*DirStore, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	return &DirStore{Directory: directory}, nil
}

func (store *DirStore) Append(line string) error {
	handle, err := os.OpenFile(filepath.Join(store.Directory, "log.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer handle.Close()
	if _, err := handle.WriteString(line + "\n"); err != nil {
		return err
	}
	return handle.Sync()
}

func (store *DirStore) LoadLines() ([]string, error) {
	data, err := os.ReadFile(filepath.Join(store.Directory, "log.jsonl"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var lines []string
	start := 0
	for index, character := range data {
		if character == '\n' {
			lines = append(lines, string(data[start:index]))
			start = index + 1
		}
	}
	if start < len(data) {
		lines = append(lines, string(data[start:]))
	}
	return lines, nil
}

func (store *DirStore) SaveVotes(votes Obj) error {
	return writeAtomic(filepath.Join(store.Directory, "votes.json"), Marshal(votes), 0o600)
}

func (store *DirStore) LoadVotes() Obj {
	data, err := os.ReadFile(filepath.Join(store.Directory, "votes.json"))
	if err != nil {
		return Obj{}
	}
	votes, err := DecodeObj(data)
	if err != nil {
		return Obj{}
	}
	return votes
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".new-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		os.Remove(name)
		return err
	}
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		os.Remove(name)
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		os.Remove(name)
		return err
	}
	temporary.Close()
	return os.Rename(name, path)
}
