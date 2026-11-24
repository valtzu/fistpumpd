package cluster

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"testing"
)

func vectors(t *testing.T) Obj {
	t.Helper()
	data, err := os.ReadFile("../testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	document, err := DecodeObj(data)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func TestCanonicalVectors(t *testing.T) {
	for _, item := range vectors(t)["canonical"].([]any) {
		c := item.(Obj)
		got, err := Canonical(c["value"])
		if err != nil {
			t.Fatalf("%v: %v", c["value"], err)
		}
		if string(got) != c["canonical"] {
			t.Errorf("canonical %v:\n got %s\nwant %s", c["value"], got, c["canonical"])
		}
		digest, _ := Digest(c["value"])
		if digest != c["sha256"] {
			t.Errorf("digest %v", c["value"])
		}
	}
}

func TestCanonicalRejectsFractions(t *testing.T) {
	if _, err := Canonical(Obj{"a": 1.5}); err == nil {
		t.Fatal("fractions must be refused")
	}
	if _, err := Canonical(Obj{"a": json.Number("1e3")}); err == nil {
		t.Fatal("exponents must be refused")
	}
}

func TestQuorumVectors(t *testing.T) {
	for _, item := range vectors(t)["quorum"].([]any) {
		pair := item.([]any)
		if got := Quorum(pair[0].(int)); got != pair[1].(int) {
			t.Errorf("quorum(%v) = %d, want %v", pair[0], got, pair[1])
		}
	}
}

func TestSelectorVectors(t *testing.T) {
	for _, item := range vectors(t)["selector"].([]any) {
		c := item.(Obj)
		if got := Matches(c["selector"].(Obj), c["facts"].(Obj)); got != c["match"].(bool) {
			t.Errorf("selector %v facts %v: got %v", c["selector"], c["facts"], got)
		}
	}
}

func TestTopologyVectors(t *testing.T) {
	data := vectors(t)["topology"].(Obj)
	topology, err := ParseTopology(data["document"].(Obj))
	if err != nil {
		t.Fatal(err)
	}
	if topology.Digest != data["digest"] {
		t.Errorf("digest %s want %s", topology.Digest, data["digest"])
	}
	for _, item := range data["cases"].([]any) {
		c := item.(Obj)
		var held [][]string
		for _, roles := range c["held"].([]any) {
			held = append(held, stringList(roles))
		}
		got := topology.SelectRoles(c["facts"].(Obj), held)
		if !equalStrings(got, stringList(c["roles"])) {
			t.Errorf("facts %v held %v: got %v want %v", c["facts"], held, got, c["roles"])
		}
		unmet := topology.Unmet(held)
		want := c["unmet"].(Obj)
		if len(unmet) != len(want) {
			t.Errorf("unmet %v want %v", unmet, want)
		}
		for role, count := range want {
			if unmet[role] != count.(int) {
				t.Errorf("unmet %s: %d want %v", role, unmet[role], count)
			}
		}
	}
	for _, item := range data["invalid"].([]any) {
		if _, err := ParseTopology(item.(Obj)); err == nil {
			t.Errorf("topology %v should be refused", item)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func TestPolicyVectors(t *testing.T) {
	data := vectors(t)["policy"].(Obj)
	policy := NewPolicy(data["document"].(Obj))
	for number, want := range data["allowed"].(Obj) {
		n, _ := asInt(json.Number(number))
		if !equalStrings(policy.Allowed[n], stringList(want)) {
			t.Errorf("allowed[%s] = %v want %v", number, policy.Allowed[n], want)
		}
	}
	for _, item := range data["cases"].([]any) {
		c := item.(Obj)
		pcrs := map[string]string{}
		for key, value := range c["pcrs"].(Obj) {
			pcrs[key] = value.(string)
		}
		image, err := policy.Check(pcrs)
		if c["ok"].(bool) {
			if err != nil || image != c["image"] {
				t.Errorf("pcrs %v: image %q err %v, want %v", pcrs, image, err, c["image"])
			}
		} else if err == nil || err.Error() != c["error"] {
			t.Errorf("pcrs %v: err %v, want %v", pcrs, err, c["error"])
		}
	}
	if _, err := NewPolicy(Obj{}).Check(map[string]string{}); err == nil || err.Error() != data["empty_error"] {
		t.Errorf("empty policy error %v want %v", err, data["empty_error"])
	}
}

func seedKey(seed int) ed25519.PrivateKey {
	bytes := make([]byte, 32)
	for i := range bytes {
		bytes[i] = byte(seed)
	}
	return ed25519.NewKeyFromSeed(bytes)
}

func TestChainVectors(t *testing.T) {
	data := vectors(t)["chain"].(Obj)
	chain := NewChain(nil)
	for _, entry := range data["entries"].([]any) {
		if err := chain.Append(entry.(Obj)); err != nil {
			t.Fatalf("entry %v: %v", entry.(Obj)["index"], err)
		}
	}
	state := data["state"].(Obj)
	if chain.Head() != state["head"] {
		t.Errorf("head %s want %s", chain.Head(), state["head"])
	}
	for slot, want := range state["members"].(Obj) {
		n, _ := asInt(json.Number(slot))
		member := chain.Members[n]
		if member == nil || member.Status != want.(Obj)["status"] || !equalStrings(member.Roles, stringList(want.(Obj)["roles"])) {
			t.Errorf("member %s = %+v want %v", slot, member, want)
		}
	}
	if chain.TopologyVersion() != integer(state["topology"].(Obj), "version") {
		t.Errorf("topology %v", chain.Topology)
	}
	rebuilt, err := ChainFromLines(chain.Lines(), nil)
	if err != nil || rebuilt.Head() != chain.Head() {
		t.Errorf("replay: %v", err)
	}
	var tampered []string
	for _, entry := range data["tampered"].([]any) {
		tampered = append(tampered, string(Marshal(entry)))
	}
	if _, err := ChainFromLines(tampered, nil); err == nil {
		t.Error("tampered history must not verify")
	}
}

func TestResetVectors(t *testing.T) {
	data := vectors(t)["reset"].(Obj)
	pem := []byte(data["certificate"].(string))
	if !VerifyBuild(pem, data["entry"].(Obj)) {
		t.Error("the build signature from the reference must verify")
	}
	if VerifyBuild(pem, data["forged"].(Obj)) {
		t.Error("a forged build signature must not verify")
	}
	chain := NewChain(pem)
	for _, entry := range vectors(t)["chain"].(Obj)["entries"].([]any) {
		if err := chain.Append(entry.(Obj)); err != nil {
			t.Fatal(err)
		}
	}
	if err := chain.Append(data["entry"].(Obj)); err != nil {
		t.Fatal(err)
	}
	if len(chain.Active()) != 2 {
		t.Errorf("active after reset: %d", len(chain.Active()))
	}
}
