package cluster

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	stdhex "encoding/hex"
	"fmt"
	"sync"
	"testing"
)

var goodPCRs = map[string]string{
	"0": repeat("a"), "1": repeat("b"), "2": repeat("c"), "3": repeat("d"), "7": repeat("e"), "11": repeat("f"),
}

func repeat(character string) string {
	text := ""
	for len(text) < 64 {
		text += character
	}
	return text[:64]
}

func policyDocument() Obj {
	return Obj{
		"firmware":             []any{Obj{"pcr0": goodPCRs["0"]}},
		"secure_boot":          Obj{"pcr7": goodPCRs["7"]},
		"versions":             []any{Obj{"version": "30", "pcr11": goodPCRs["11"], "channel": "canary"}},
		"peripheral_firmware":  []any{Obj{"pcr2": goodPCRs["2"]}},
		"eeprom_configuration": []any{Obj{"pcr3": goodPCRs["3"]}},
	}
}

func testTopology(t testing.TB) *Topology {
	t.Helper()
	topology, err := ParseTopology(Obj{
		"version": 1,
		"roles": []any{
			Obj{"name": "server", "selector": Obj{"memory-gib": ">=4"}, "min": 3, "max": 3, "conflicts": []any{"agent"}},
			Obj{"name": "agent", "selector": Obj{}, "conflicts": []any{"server"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return topology
}

var bigFacts = Obj{"memory-gib": 8, "arch": "arm64"}

type Handler interface {
	Handle(method string, payload Obj) (Obj, error)
}

type Network struct {
	mutex sync.Mutex
	nodes map[string]Handler
	down  map[string]bool
}

func NewNetwork() *Network { return &Network{nodes: map[string]Handler{}, down: map[string]bool{}} }

func (network *Network) Register(address string, handler Handler) {
	network.mutex.Lock()
	network.nodes[address] = handler
	network.mutex.Unlock()
}

func (network *Network) SetDown(address string, down bool) {
	network.mutex.Lock()
	network.down[address] = down
	network.mutex.Unlock()
}

type view struct{ network *Network }

func roundTrip(value Obj) Obj {
	if value == nil {
		return nil
	}
	copied, err := DecodeObj(Marshal(value))
	if err != nil {
		panic(err)
	}
	return copied
}

func (v view) Call(address, method string, payload Obj) (Obj, error) {
	v.network.mutex.Lock()
	handler, present := v.network.nodes[address]
	down := v.network.down[address]
	v.network.mutex.Unlock()
	if down || !present {
		return nil, &TransportError{Message: address}
	}
	reply, err := handler.Handle(method, roundTrip(payload))
	return roundTrip(reply), err
}

func (v view) Prover(address, fingerprint string) Prover {
	return RemoteProver{Call: func(method string, payload Obj) (Obj, error) { return v.Call(address, method, payload) }}
}

type testNode struct {
	key    ed25519.PrivateKey
	record Obj
	tpm    *FakeTPM
	cfg    Config
}

func newTestNode(t testing.TB, network *Network, name string, options ...func(*testNode)) *testNode {
	t.Helper()
	seed := make([]byte, 32)
	_, _ = rand.Read(seed)
	key := ed25519.NewKeyFromSeed(seed)
	tpm := NewFakeTPM(goodPCRs)
	hello, _ := tpm.Hello()
	ek, _ := EKHash(hello)
	tls := sha256.Sum256([]byte(name + "-tls"))
	node := &testNode{key: key, tpm: tpm, record: Obj{
		"sign_pub": PublicHex(key), "tls_fp": stdhex.EncodeToString(tls[:]), "ek_hash": ek, "addr": name + ".test:7000",
	}}
	node.cfg = Config{Key: key, Record: node.record, Facts: bigFacts, Store: &MemoryStore{}, Topology: testTopology(t),
		Policy: NewPolicy(policyDocument()), Verifier: FakeVerifier{}, Transport: view{network}, TPM: tpm}
	for _, option := range options {
		option(node)
	}
	return node
}

func makeFounder(t testing.TB, network *Network, name string, options ...func(*testNode)) *Node {
	t.Helper()
	candidate := newTestNode(t, network, name, options...)
	founder, err := Found(candidate.cfg)
	if err != nil {
		t.Fatal(err)
	}
	network.Register(str(candidate.record, "addr"), founder)
	return founder
}

func admit(t testing.TB, network *Network, joiner *testNode, sponsor *Node) (*Node, error) {
	t.Helper()
	network.Register(str(joiner.record, "addr"), NewCandidate(joiner.cfg))
	member, err := NewCandidate(joiner.cfg).Join([]string{str(sponsor.Record(), "addr")})
	if err != nil {
		return nil, err
	}
	network.Register(str(joiner.record, "addr"), member)
	return member, nil
}

func makeCluster(t testing.TB, network *Network, count int) []*Node {
	t.Helper()
	nodes := []*Node{makeFounder(t, network, "n0")}
	for index := 1; index < count; index++ {
		member, err := admit(t, network, newTestNode(t, network, fmt.Sprintf("n%d", index)), nodes[0])
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, member)
	}
	return nodes
}

func signHex(key ed25519.PrivateKey, message []byte) string {
	return fmt.Sprintf("%x", ed25519.Sign(key, message))
}
