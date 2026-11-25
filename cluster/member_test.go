package cluster

import (
	"errors"
	"strings"
	"testing"
)

func rolesOf(node *Node, slot int) []string {
	var roles []string
	node.WithLog(func(log *Chain) { roles = log.Member(slot).Roles })
	return roles
}

func TestThreeNodesGetSlotsAndRolesInOrder(t *testing.T) {
	nodes := makeCluster(t, NewNetwork(), 3)
	for index, node := range nodes {
		active, head, length, _ := node.Snapshot()
		if length != 3 || head != nodes[0].Log.Head() || len(active) != 3 || node.Slot() != index {
			t.Fatalf("node %d: length %d slots %d", index, length, node.Slot())
		}
		if !equalStrings(rolesOf(node, index), []string{"server"}) {
			t.Fatalf("roles %v", rolesOf(node, index))
		}
	}
}

func TestServerCapMakesTheFourthAnAgent(t *testing.T) {
	nodes := makeCluster(t, NewNetwork(), 4)
	if !equalStrings(rolesOf(nodes[3], 3), []string{"agent"}) {
		t.Fatalf("roles %v", rolesOf(nodes[3], 3))
	}
}

func TestSmallNodeIsAnAgent(t *testing.T) {
	network := NewNetwork()
	founder := makeFounder(t, network, "n0")
	small := newTestNode(t, network, "small", func(n *testNode) { n.cfg.Facts = Obj{"memory-gib": 2} })
	member, err := admit(t, network, small, founder)
	if err != nil || !equalStrings(rolesOf(member, 1), []string{"agent"}) {
		t.Fatalf("%v %v", err, member)
	}
}

func refusedWith(t *testing.T, err error, substring string) {
	t.Helper()
	var refused *Refused
	if !errors.As(err, &refused) || !strings.Contains(refused.Reason, substring) {
		t.Fatalf("want refusal containing %q, got %v", substring, err)
	}
}

func TestUnknownFirmwareIsRefused(t *testing.T) {
	network := NewNetwork()
	founder := makeFounder(t, network, "n0")
	bad := NewFakeTPM(map[string]string{"0": goodPCRs["0"], "1": goodPCRs["1"], "2": goodPCRs["2"], "3": goodPCRs["3"], "7": goodPCRs["7"], "11": repeat("9")})
	stranger := newTestNode(t, network, "stranger", func(n *testNode) {
		n.tpm, n.cfg.TPM = bad, bad
		hello, _ := bad.Hello()
		n.record["ek_hash"], _ = EKHash(hello)
	})
	_, err := admit(t, network, stranger, founder)
	refusedWith(t, err, "PCR 11")
	if founder.Log.Len() != 1 {
		t.Fatal("the log must not grow")
	}
}

func TestLyingAboutTheEndorsementKeyIsRefused(t *testing.T) {
	network := NewNetwork()
	founder := makeFounder(t, network, "n0")
	liar := newTestNode(t, network, "liar", func(n *testNode) { n.record["ek_hash"] = repeat("1") })
	_, err := admit(t, network, liar, founder)
	refusedWith(t, err, "endorsement key")
}

type forgingTPM struct{ *FakeTPM }

func (forged forgingTPM) Quote(nonce, signPub, tlsFP string) (Obj, error) {
	quote, _ := forged.FakeTPM.Quote(nonce, signPub, tlsFP)
	pcrs := Obj{}
	for key, value := range goodPCRs {
		pcrs[key] = value
	}
	quote["pcrs"] = pcrs
	return quote, nil
}

func TestPCRValuesForgedWithoutTheAttestationKeyAreRefused(t *testing.T) {
	network := NewNetwork()
	founder := makeFounder(t, network, "n0")
	real := NewFakeTPM(map[string]string{"0": repeat("1"), "1": goodPCRs["1"], "2": goodPCRs["2"], "3": goodPCRs["3"], "7": goodPCRs["7"], "11": goodPCRs["11"]})
	forger := newTestNode(t, network, "forger", func(n *testNode) {
		n.tpm, n.cfg.TPM = real, forgingTPM{real}
		hello, _ := real.Hello()
		n.record["ek_hash"], _ = EKHash(hello)
	})
	_, err := admit(t, network, forger, founder)
	refusedWith(t, err, "signature")
}

func TestEveryMemberHoldsTheSameChain(t *testing.T) {
	nodes := makeCluster(t, NewNetwork(), 5)
	for _, node := range nodes {
		if node.Log.Head() != nodes[0].Log.Head() {
			t.Fatal("heads differ")
		}
	}
}

func TestLateJoinerReplaysTheHistory(t *testing.T) {
	network := NewNetwork()
	nodes := makeCluster(t, network, 4)
	late, err := admit(t, network, newTestNode(t, network, "late"), nodes[2])
	if err != nil || late.Log.Len() != 5 || late.Log.Head() != nodes[0].Log.Head() {
		t.Fatalf("%v", err)
	}
}

func TestQuorumSurvivesOneNodeDown(t *testing.T) {
	network := NewNetwork()
	nodes := makeCluster(t, network, 4)
	network.SetDown(str(nodes[3].Record(), "addr"), true)
	member, err := admit(t, network, newTestNode(t, network, "n4"), nodes[0])
	if err != nil || len(member.Log.Active()) != 5 {
		t.Fatalf("%v", err)
	}
}

func TestNoQuorumMeansNoAdmission(t *testing.T) {
	network := NewNetwork()
	nodes := makeCluster(t, network, 3)
	network.SetDown(str(nodes[1].Record(), "addr"), true)
	network.SetDown(str(nodes[2].Record(), "addr"), true)
	_, err := admit(t, network, newTestNode(t, network, "n3"), nodes[0])
	refusedWith(t, err, "signatures")
	if nodes[0].Log.Len() != 3 {
		t.Fatal("the log must not grow")
	}
}

func TestADuplicateNodeCannotJoinTwice(t *testing.T) {
	network := NewNetwork()
	nodes := makeCluster(t, network, 3)
	again := newTestNode(t, network, "again", func(n *testNode) {
		n.tpm, n.cfg.TPM = nodes[1].cfg.TPM.(*FakeTPM), nodes[1].cfg.TPM
		hello, _ := n.tpm.Hello()
		n.record["ek_hash"], _ = EKHash(hello)
		n.record["sign_pub"] = nodes[1].Record()["sign_pub"]
	})
	if _, err := admit(t, network, again, nodes[0]); err == nil {
		t.Fatal("a member cannot join twice")
	}
}

func TestTwoSponsorsForOneIndexEndInOneOrder(t *testing.T) {
	network := NewNetwork()
	nodes := makeCluster(t, network, 3)
	first, second := newTestNode(t, network, "x"), newTestNode(t, network, "y")
	network.Register("x.test:7000", NewCandidate(first.cfg))
	network.Register("y.test:7000", NewCandidate(second.cfg))
	a, err := nodes[0].Handle("join", Obj{"node": first.record, "facts": first.cfg.Facts})
	if err != nil {
		t.Fatal(err)
	}
	b, err := nodes[1].Handle("join", Obj{"node": second.record, "facts": second.cfg.Facts})
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes {
		node.CatchUp()
	}
	if nodes[0].Log.Len() != 5 || a["entry"].(Obj)["index"] == b["entry"].(Obj)["index"] {
		t.Fatalf("length %d", nodes[0].Log.Len())
	}
}

func TestAStaleLockIsFinishedByTheNextSponsor(t *testing.T) {
	network := NewNetwork()
	nodes := makeCluster(t, network, 3)
	first, second := newTestNode(t, network, "x"), newTestNode(t, network, "y")
	network.Register("x.test:7000", NewCandidate(first.cfg))
	network.Register("y.test:7000", NewCandidate(second.cfg))
	nodes[0].beforeCommit = func(Obj) error { return &TransportError{Message: "crashed before the commit"} }
	if _, err := nodes[0].Handle("join", Obj{"node": first.record, "facts": first.cfg.Facts}); err == nil {
		t.Fatal("the first sponsor crashes before the commit")
	}
	nodes[0].beforeCommit = nil
	if nodes[0].Log.Len() != 3 {
		t.Fatal("nothing was committed")
	}
	if _, err := nodes[1].Handle("join", Obj{"node": second.record, "facts": second.cfg.Facts}); err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes {
		node.CatchUp()
	}
	if nodes[1].Log.Len() != 5 {
		t.Fatalf("length %d", nodes[1].Log.Len())
	}
}

func TestVotesSurviveARestart(t *testing.T) {
	network := NewNetwork()
	nodes := makeCluster(t, network, 3)
	joiner := newTestNode(t, network, "x")
	network.Register("x.test:7000", NewCandidate(joiner.cfg))
	if _, err := nodes[0].Handle("join", Obj{"node": joiner.record, "facts": joiner.cfg.Facts}); err != nil {
		t.Fatal(err)
	}
	if len(nodes[1].cfg.Store.LoadVotes()) != len(nodes[1].votes) {
		t.Fatal("votes are not persisted")
	}
}

func TestALockExpires(t *testing.T) {
	network := NewNetwork()
	now := 1000.0
	nodes := makeCluster(t, network, 3)
	nodes[1].cfg.Clock = func() float64 { return now }
	entry := Obj{"index": 3, "prev": nodes[0].Log.Head(), "type": "admit", "body": Obj{}}
	nodes[1].votes["3"] = Obj{"hash": repeat("a"), "time": int(now), "entry": entry}
	proposal := Obj{"index": 3, "prev": entry["prev"], "type": "admit", "body": Obj{"x": 1}}
	var refused *Refused
	if err := nodes[1].lock(proposal); !errors.As(err, &refused) || !strings.Contains(refused.Reason, "already voted") {
		t.Fatalf("%v", err)
	}
	now += VoteLockSeconds + 1
	if err := nodes[1].lock(proposal); err != nil {
		t.Fatal(err)
	}
}

type watching map[int]bool

func (w watching) Healthy(member *Member) bool { return !w[member.Slot] }

func TestMembersThatSeeTheFailureEvict(t *testing.T) {
	nodes := makeCluster(t, NewNetwork(), 4)
	for _, node := range nodes {
		node.SetObserver(watching{3: true})
	}
	if _, err := nodes[0].ProposeEvict(3, "attestation failed"); err != nil {
		t.Fatal(err)
	}
	if got := sortedSlots(mustActive(nodes[1])); !equalInts(got, []int{0, 1, 2}) {
		t.Fatalf("%v", got)
	}
}

func mustActive(node *Node) []*Member {
	active, _, _, _ := node.Snapshot()
	return active
}

func equalInts(a, b []int) bool {
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

func TestAMemberThatSeesItHealthyDoesNotSign(t *testing.T) {
	nodes := makeCluster(t, NewNetwork(), 4)
	nodes[0].SetObserver(watching{3: true})
	for _, node := range nodes[1:] {
		node.SetObserver(watching{})
	}
	_, err := nodes[0].ProposeEvict(3, "suspicion")
	refusedWith(t, err, "signatures")
	if len(mustActive(nodes[0])) != 4 {
		t.Fatal("nobody must be evicted")
	}
}

func newerTopology(t *testing.T, version int) *Topology {
	topology, err := ParseTopology(Obj{"version": version, "roles": []any{
		Obj{"name": "server", "selector": Obj{}, "max": 3}, Obj{"name": "agent", "selector": Obj{}, "conflicts": []any{"server"}}}})
	if err != nil {
		t.Fatal(err)
	}
	return topology
}

func TestAdoptingANewTopologyIsLogged(t *testing.T) {
	nodes := makeCluster(t, NewNetwork(), 3)
	for _, node := range nodes {
		node.SetTopology(newerTopology(t, 2))
	}
	if _, err := nodes[1].ProposeTopology(); err != nil {
		t.Fatal(err)
	}
	if nodes[0].Log.TopologyVersion() != 2 {
		t.Fatal("topology not adopted")
	}
}

func TestANodeWithAnOlderTopologyRefusesToSign(t *testing.T) {
	nodes := makeCluster(t, NewNetwork(), 3)
	nodes[0].SetTopology(newerTopology(t, 2))
	_, err := nodes[0].ProposeTopology()
	refusedWith(t, err, "signatures")
}

type tokenStub map[string]string

func (stub tokenStub) Get(kind string) string { return stub[kind] }

func TestMembersFetchTokensByRole(t *testing.T) {
	nodes := makeCluster(t, NewNetwork(), 4)
	nodes[0].SetTokens(tokenStub{"server": "s3cret", "agent": "a9ent"})
	if nodes[1].FetchToken("server") != "s3cret" || nodes[3].FetchToken("agent") != "a9ent" || nodes[3].FetchToken("server") != "" {
		t.Fatal("tokens must follow the roles")
	}
}

func TestAReplayedTokenRequestGetsNothing(t *testing.T) {
	nodes := makeCluster(t, NewNetwork(), 3)
	nodes[0].SetTokens(tokenStub{"server": "s3cret"})
	reply, _ := nodes[0].Handle("token_challenge", Obj{})
	nonce := reply["nonce"].(string)
	signature := signHex(nodes[1].cfg.Key, TokenRequest("server", nonce, 1))
	request := Obj{"kind": "server", "nonce": nonce, "slot": 1, "sig": signature}
	if got, err := nodes[0].Handle("token", request); err != nil || got["token"] != "s3cret" {
		t.Fatalf("%v", err)
	}
	if _, err := nodes[0].Handle("token", request); err == nil {
		t.Fatal("a replay must fail")
	}
}

func TestAnOutsiderGetsNoToken(t *testing.T) {
	network := NewNetwork()
	nodes := makeCluster(t, network, 3)
	nodes[0].SetTokens(tokenStub{"server": "s3cret"})
	outsider := newTestNode(t, network, "out")
	reply, _ := nodes[0].Handle("token_challenge", Obj{})
	nonce := reply["nonce"].(string)
	signature := signHex(outsider.key, TokenRequest("server", nonce, 1))
	if _, err := nodes[0].Handle("token", Obj{"kind": "server", "nonce": nonce, "slot": 1, "sig": signature}); err == nil {
		t.Fatal("an outsider must get nothing")
	}
}
