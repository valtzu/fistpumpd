package cluster

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAYAMLTopologyIsParsedLikeJSON(t *testing.T) {
	directory := t.TempDir()
	asJSON := `{"version": 3, "roles": [{"name": "server", "min": 1, "max": 3}], "files": [{"path": "/run/x", "template": ["a", "b {{.Count \"server\"}}"]}]}`
	asYAML := "version: 3\nroles:\n  - {name: server, min: 1, max: 3}\nfiles:\n  - path: /run/x\n    template: |\n      a\n      b {{.Count \"server\"}}\n"
	write := func(name, text string) *Topology {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		document, err := ReadTopologyFile(path)
		if err != nil {
			t.Fatal(err)
		}
		topology, err := ParseTopology(document)
		if err != nil {
			t.Fatal(err)
		}
		return topology
	}
	fromJSON, fromYAML := write("topology.json", asJSON), write("topology.yaml", asYAML)
	if fromJSON.Version != 3 || fromYAML.Version != 3 {
		t.Fatalf("versions %d and %d", fromJSON.Version, fromYAML.Version)
	}
	if len(fromYAML.Files) != 1 {
		t.Fatalf("files not parsed: %+v", fromYAML.Files)
	}
}
