package cluster

import "testing"

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
