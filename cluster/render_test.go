package cluster

import (
	"os"
	"path/filepath"
	"testing"
)

func TestATemplateMayBeAListOfLines(t *testing.T) {
	files, err := parseFiles([]any{Obj{"path": "/etc/x", "template": []any{"a", "{{.Slot}}", "b"}}})
	if err != nil {
		t.Fatal(err)
	}
	text, err := (&View{Slot: 4}).render(files[0])
	if err != nil || text != "a\n4\nb" {
		t.Fatalf("%q %v", text, err)
	}
	if _, err := parseFiles([]any{Obj{"path": "/etc/x", "template": []any{1}}}); err == nil {
		t.Fatal("a list of lines holds strings")
	}
	if _, err := parseFiles([]any{Obj{"path": "/etc/x", "template": "{{.Missing"}}); err == nil {
		t.Fatal("a broken template is refused when the topology is parsed")
	}
}

func TestAddressesListTheHoldersOfARole(t *testing.T) {
	view := &View{holders: map[string][]int{"server": {2, 0}}, addresses: map[int]string{0: "10.0.0.1:17947", 2: "10.0.0.3:17947"}}
	got := view.Addresses("server")
	if len(got) != 2 || got[0] != "10.0.0.3" || got[1] != "10.0.0.1" {
		t.Fatalf("%v", got)
	}
}

func TestTheTopologyFileIsChosenWhenItIsRead(t *testing.T) {
	dir := t.TempDir()
	first, second := filepath.Join(dir, "etc.json"), filepath.Join(dir, "usr.json")
	_ = os.WriteFile(second, []byte("{}"), 0o644)
	daemon := &Daemon{cfg: DaemonConfig{Paths: Paths{Topology: second, Topologies: []string{first, second}}}}
	if daemon.topologyPath() != second {
		t.Fatal("the fallback is used while the first file is missing")
	}
	_ = os.WriteFile(first, []byte("{}"), 0o644)
	if daemon.topologyPath() != first {
		t.Fatal("the first file is used once it exists")
	}
}
