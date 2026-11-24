package cluster

import "testing"

func TestStructuredSelectors(t *testing.T) {
	facts := Obj{"arch": "arm64", "memory-gib": 8, "board": "rpi4"}
	cases := []struct {
		selector Obj
		want     bool
	}{
		{Obj{"matchLabels": Obj{"arch": "arm64"}}, true},
		{Obj{"matchLabels": Obj{"arch": "amd64"}}, false},
		{Obj{"matchExpressions": []any{Obj{"key": "memory-gib", "operator": "Gt", "values": []any{"3"}}}}, true},
		{Obj{"matchExpressions": []any{Obj{"key": "memory-gib", "operator": "Lt", "values": []any{"8"}}}}, false},
		{Obj{"matchExpressions": []any{Obj{"key": "board", "operator": "In", "values": []any{"rpi4", "rpi5"}}}}, true},
		{Obj{"matchExpressions": []any{Obj{"key": "board", "operator": "NotIn", "values": []any{"rpi4"}}}}, false},
		{Obj{"matchExpressions": []any{Obj{"key": "tpm", "operator": "DoesNotExist"}}}, true},
		{Obj{"matchExpressions": []any{Obj{"key": "tpm", "operator": "Exists"}}}, false},
		{Obj{"matchLabels": Obj{"arch": "arm64"}, "memory-gib": ">=16"}, false},
	}
	for index, c := range cases {
		if err := ValidateSelector(c.selector); err != nil {
			t.Fatalf("case %d: %v", index, err)
		}
		if got := Matches(c.selector, facts); got != c.want {
			t.Errorf("case %d: %v, want %v", index, got, c.want)
		}
	}
	for _, bad := range []Obj{
		{"matchExpressions": []any{Obj{"key": "arch", "operator": "Between", "values": []any{"1"}}}},
		{"matchExpressions": []any{Obj{"key": "arch", "operator": "Gt", "values": []any{"x"}}}},
		{"matchLabels": []any{}},
	} {
		if err := ValidateSelector(bad); err == nil {
			t.Errorf("%v should be refused", bad)
		}
	}
}
