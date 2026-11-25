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

func TestATemplateFileIsReadIntoTheTopologyAndChangesItsDigest(t *testing.T) {
	directory := t.TempDir()
	if err := os.MkdirAll(filepath.Join(directory, "templates"), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, text string) {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	topology := func() *Topology {
		document, err := ReadTopologyFile(filepath.Join(directory, "topology.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseTopology(document)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	write("topology.yaml", "version: 1\nroles:\n  - {name: server}\nfiles:\n  - path: /run/x\n    template_file: templates/x.tmpl\n")
	write("templates/x.tmpl", "hello {{.Count \"server\"}}\n\n")
	first := topology()
	spec := first.Document["files"].([]any)[0].(Obj)
	if spec["template"] != "hello {{.Count \"server\"}}" || spec["template_file"] != nil {
		t.Fatalf("spec %v", spec)
	}
	write("templates/x.tmpl", "bye\n")
	if topology().Digest == first.Digest {
		t.Fatal("the digest must cover the template's content")
	}
}

func TestATemplateFileCannotLeaveTheTopologyDirectory(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "topology.yaml")
	text := "version: 1\nfiles:\n  - path: /run/x\n    template_file: ../secret\n"
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTopologyFile(path); err == nil {
		t.Fatal("expected a refusal")
	}
}
