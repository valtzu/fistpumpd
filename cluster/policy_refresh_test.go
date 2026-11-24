package cluster

import "testing"

func TestAPolicyIsRefreshedWhenItRefusesAMeasurement(t *testing.T) {
	stale := Obj{}
	for key, value := range policyDocument() {
		stale[key] = value
	}
	stale["versions"] = []any{}
	refreshes := 0
	node := &Node{cfg: Config{PolicyRefresh: func() *Policy {
		refreshes++
		return NewPolicy(policyDocument())
	}}, policy: NewPolicy(stale)}
	if _, err := node.checkPolicy(goodPCRs); err != nil {
		t.Fatalf("a refreshed policy should accept the measurement: %v", err)
	}
	if refreshes != 1 {
		t.Fatalf("refreshed %d times, want 1", refreshes)
	}
}

func TestAMeasurementThatStaysRefusedIsRefusedAfterOneRefresh(t *testing.T) {
	refreshes := 0
	node := &Node{cfg: Config{PolicyRefresh: func() *Policy {
		refreshes++
		return NewPolicy(Obj{})
	}}, policy: NewPolicy(Obj{})}
	if _, err := node.checkPolicy(goodPCRs); err == nil {
		t.Fatal("expected a refusal")
	}
	if refreshes != 1 {
		t.Fatalf("refreshed %d times, want 1", refreshes)
	}
}
