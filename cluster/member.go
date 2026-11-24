package cluster

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"
)

const (
	VoteLockSeconds = 300.0
	MaxRounds       = 5
)

type Refused struct {
	Reason  string
	Pending Obj
}

func (r *Refused) Error() string { return r.Reason }

func refuse(format string, args ...any) error { return &Refused{Reason: fmt.Sprintf(format, args...)} }

type TransportError struct{ Message string }

func (e *TransportError) Error() string { return e.Message }

var errSuperseded = errors.New("superseded")

type Transport interface {
	Call(address, method string, payload Obj) (Obj, error)
	Prover(address, fingerprint string) Prover
}

type Observer interface{ Healthy(member *Member) bool }

type TokenSource interface{ Get(kind string) string }

type Config struct {
	Key              ed25519.PrivateKey
	Record           Obj
	Facts            Obj
	Store            Store
	Topology         *Topology
	Policy           *Policy
	Verifier         Verifier
	Transport        Transport
	BuildCertificate []byte
	Observer         Observer
	Clock            func() float64
	OnChange         func(*Node)
	TPM              Prover
	Tokens           TokenSource
}

func (cfg *Config) clock() float64 {
	if cfg.Clock != nil {
		return cfg.Clock()
	}
	return float64(time.Now().UnixNano()) / 1e9
}

type Node struct {
	cfg          Config
	mu           sync.Mutex
	Log          *Chain
	votes        Obj
	challenges   map[string]float64
	topology     *Topology
	policy       *Policy
	observer     Observer
	tokens       TokenSource
	onChange     func(*Node)
	beforeCommit func(Obj) error
}

func newNode(cfg Config, log *Chain) *Node {
	node := &Node{cfg: cfg, Log: log, votes: cfg.Store.LoadVotes(), challenges: map[string]float64{},
		topology: cfg.Topology, policy: cfg.Policy, observer: cfg.Observer, tokens: cfg.Tokens, onChange: cfg.OnChange}
	return node
}

func Found(cfg Config) (*Node, error) {
	chain := NewChain(cfg.BuildCertificate)
	topology := cfg.Topology
	roles := topology.SelectRoles(cfg.Facts, nil)
	body := Obj{
		"node": cfg.Record, "roles": toAny(roles), "facts": cfg.Facts, "founder": true,
		"topology": Obj{"version": topology.Version, "digest": topology.Digest}, "policy": Obj{},
	}
	entry := Obj{"index": 0, "prev": Zero, "type": "admit", "body": body}
	entry["sigs"] = Obj{"0": SignEntry(cfg.Key, entry)}
	if err := chain.Append(entry); err != nil {
		return nil, err
	}
	if err := cfg.Store.Append(string(Marshal(entry))); err != nil {
		return nil, err
	}
	return newNode(cfg, chain), nil
}

func Restore(cfg Config) (*Node, error) {
	lines, err := cfg.Store.LoadLines()
	if err != nil {
		return nil, err
	}
	chain, err := ChainFromLines(lines, cfg.BuildCertificate)
	if err != nil {
		return nil, err
	}
	return newNode(cfg, chain), nil
}

func (node *Node) Record() Obj { return node.cfg.Record }

func (node *Node) Slot() int {
	node.mu.Lock()
	defer node.mu.Unlock()
	return node.Log.SlotOf(str(node.cfg.Record, "sign_pub"))
}

func (node *Node) slotLocked() int { return node.Log.SlotOf(str(node.cfg.Record, "sign_pub")) }

func (node *Node) Topology() *Topology {
	node.mu.Lock()
	defer node.mu.Unlock()
	return node.topology
}

func (node *Node) SetTopology(topology *Topology) {
	node.mu.Lock()
	node.topology = topology
	node.mu.Unlock()
}

func (node *Node) Policy() *Policy {
	node.mu.Lock()
	defer node.mu.Unlock()
	return node.policy
}

func (node *Node) SetPolicy(policy *Policy) {
	node.mu.Lock()
	node.policy = policy
	node.mu.Unlock()
}

func (node *Node) SetObserver(observer Observer) {
	node.mu.Lock()
	node.observer = observer
	node.mu.Unlock()
}

func (node *Node) SetOnChange(callback func(*Node)) {
	node.mu.Lock()
	node.onChange = callback
	node.mu.Unlock()
}

func (node *Node) SetTokens(tokens TokenSource) {
	node.mu.Lock()
	node.tokens = tokens
	node.mu.Unlock()
}

func (node *Node) SetTPM(tpm Prover) {
	node.mu.Lock()
	node.cfg.TPM = tpm
	node.mu.Unlock()
}

func (node *Node) Snapshot() (active []*Member, head string, length int, topologyVersion int) {
	node.mu.Lock()
	defer node.mu.Unlock()
	for _, member := range node.Log.Active() {
		copied := *member
		active = append(active, &copied)
	}
	return active, node.Log.Head(), node.Log.Len(), node.Log.TopologyVersion()
}

func (node *Node) WithLog(callback func(*Chain)) {
	node.mu.Lock()
	defer node.mu.Unlock()
	callback(node.Log)
}

func (node *Node) peers() []*Member {
	node.mu.Lock()
	defer node.mu.Unlock()
	var peers []*Member
	for _, member := range node.Log.Active() {
		if member.SignPub() != str(node.cfg.Record, "sign_pub") {
			copied := *member
			peers = append(peers, &copied)
		}
	}
	return peers
}

func (node *Node) call(member *Member, method string, payload Obj) (Obj, error) {
	return node.cfg.Transport.Call(member.Addr(), method, payload)
}

func (node *Node) Handle(method string, payload Obj) (Obj, error) {
	if len(method) > 7 && method[:7] == "attest_" {
		node.mu.Lock()
		tpm := node.cfg.TPM
		node.mu.Unlock()
		if tpm != nil {
			reply, _, err := ServeAttestation(tpm, method, payload)
			return reply, err
		}
	}
	switch method {
	case "hello":
		node.mu.Lock()
		defer node.mu.Unlock()
		return Obj{"sign_pub": str(node.cfg.Record, "sign_pub"), "length": node.Log.Len(), "head": node.Log.Head()}, nil
	case "log":
		return node.onLog(payload), nil
	case "commit":
		entry, _ := payload["entry"].(Obj)
		if err := node.Accept(entry); err != nil {
			return nil, refuse("%s", err.Error())
		}
		return Obj{"length": node.Log.Len()}, nil
	case "propose":
		return node.onPropose(payload)
	case "join":
		return node.onJoin(payload)
	case "token_challenge":
		return node.onTokenChallenge(), nil
	case "token":
		return node.onToken(payload)
	}
	return nil, refuse("unknown method %s", method)
}

func (node *Node) onLog(payload Obj) Obj {
	node.mu.Lock()
	defer node.mu.Unlock()
	start, _ := asInt(payload["from"])
	entries := []any{}
	if start >= 0 && start < len(node.Log.Entries) {
		for _, entry := range node.Log.Entries[start:] {
			entries = append(entries, entry)
		}
	}
	return Obj{"entries": entries}
}

func TokenRequest(kind, nonce string, slot int) []byte {
	return []byte(fmt.Sprintf("rpi-cluster token %s %s %d", kind, nonce, slot))
}

func (node *Node) onTokenChallenge() Obj {
	node.mu.Lock()
	defer node.mu.Unlock()
	now := node.cfg.clock()
	for nonce, issued := range node.challenges {
		if now-issued >= 60 {
			delete(node.challenges, nonce)
		}
	}
	nonce := NewNonce()
	node.challenges[nonce] = now
	return Obj{"nonce": nonce}
}

func (node *Node) onToken(payload Obj) (Obj, error) {
	kind, nonce := str(payload, "kind"), str(payload, "nonce")
	node.mu.Lock()
	defer node.mu.Unlock()
	_, known := node.challenges[nonce]
	delete(node.challenges, nonce)
	if node.tokens == nil || (kind != "server" && kind != "agent") || !known {
		return nil, refuse("no such challenge")
	}
	slot, ok := asInt(payload["slot"])
	var requester *Member
	if ok {
		requester = node.Log.Member(slot)
	}
	if requester == nil || !VerifyMessage(requester.SignPub(), TokenRequest(kind, nonce, slot), str(payload, "sig")) {
		return nil, refuse("not an active member")
	}
	allowed := []string{"server"}
	if kind == "agent" {
		allowed = []string{"server", "agent"}
	}
	permitted := false
	for _, role := range requester.Roles {
		permitted = permitted || contains(allowed, role)
	}
	if !permitted {
		return nil, refuse("this member's roles do not allow that token")
	}
	value := node.tokens.Get(kind)
	if value == "" {
		return nil, refuse("this member has no such token")
	}
	return Obj{"token": value}, nil
}

func (node *Node) FetchToken(kind string) string {
	for _, peer := range node.peers() {
		reply, err := node.call(peer, "token_challenge", Obj{})
		if err != nil {
			continue
		}
		nonce := str(reply, "nonce")
		slot := node.Slot()
		signature := fmt.Sprintf("%x", ed25519.Sign(node.cfg.Key, TokenRequest(kind, nonce, slot)))
		answer, err := node.call(peer, "token", Obj{"kind": kind, "nonce": nonce, "slot": slot, "sig": signature})
		if err != nil {
			continue
		}
		if token := str(answer, "token"); token != "" {
			return token
		}
	}
	return ""
}

func (node *Node) Accept(entry Obj) error {
	if entry == nil {
		return fmt.Errorf("no entry")
	}
	index, _ := asInt(entry["index"])
	node.mu.Lock()
	length := node.Log.Len()
	node.mu.Unlock()
	if index > length {
		node.CatchUp()
	}
	node.mu.Lock()
	if index != node.Log.Len() {
		node.mu.Unlock()
		return nil
	}
	if err := node.Log.Append(entry); err != nil {
		node.mu.Unlock()
		return err
	}
	if err := node.cfg.Store.Append(string(Marshal(entry))); err != nil {
		node.mu.Unlock()
		return err
	}
	for key := range node.votes {
		if number, _ := strconv.Atoi(key); number <= index {
			delete(node.votes, key)
		}
	}
	_ = node.cfg.Store.SaveVotes(node.votes)
	callback := node.onChange
	node.mu.Unlock()
	if callback != nil {
		callback(node)
	}
	return nil
}

func (node *Node) CatchUp() {
	for _, peer := range node.peers() {
		node.mu.Lock()
		from := node.Log.Len()
		node.mu.Unlock()
		reply, err := node.call(peer, "log", Obj{"from": from})
		if err != nil {
			continue
		}
		entries, _ := reply["entries"].([]any)
		for _, item := range entries {
			if entry, ok := item.(Obj); ok {
				node.mu.Lock()
				next := node.Log.Len()
				node.mu.Unlock()
				if index, _ := asInt(entry["index"]); index == next {
					_ = node.Accept(entry)
				}
			}
		}
		if len(entries) > 0 {
			return
		}
	}
}

func (node *Node) lock(entry Obj) error {
	key := strconv.Itoa(integer(entry, "index"))
	digest := EntryHash(entry)
	node.mu.Lock()
	defer node.mu.Unlock()
	if held, ok := node.votes[key].(Obj); ok && str(held, "hash") != digest {
		issued, _ := asInt(held["time"])
		if node.cfg.clock()-float64(issued) < VoteLockSeconds {
			pending, _ := held["entry"].(Obj)
			return &Refused{Reason: "already voted for another entry at this index", Pending: pending}
		}
	}
	node.votes[key] = Obj{"hash": digest, "time": int(node.cfg.clock()), "entry": entry}
	return node.cfg.Store.SaveVotes(node.votes)
}

func core(entry Obj) Obj {
	return Obj{"index": entry["index"], "prev": entry["prev"], "type": entry["type"], "body": entry["body"]}
}

func (node *Node) shape(entry Obj) error {
	check := func() (bool, bool) {
		node.mu.Lock()
		defer node.mu.Unlock()
		index, _ := asInt(entry["index"])
		return index == node.Log.Len(), str(entry, "prev") == node.Log.Head()
	}
	if indexOK, prevOK := check(); !indexOK || !prevOK {
		node.CatchUp()
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	index, _ := asInt(entry["index"])
	if index != node.Log.Len() {
		return refuse("index %v is not the next one (%d)", entry["index"], node.Log.Len())
	}
	if str(entry, "prev") != node.Log.Head() {
		return refuse("prev does not match the head")
	}
	switch str(entry, "type") {
	case "admit", "evict", "topology":
		return nil
	}
	return refuse("this entry type is not voted on")
}

func (node *Node) validate(entry Obj) error {
	switch str(entry, "type") {
	case "admit":
		return node.validateAdmit(entry)
	case "evict":
		return node.validateEvict(entry)
	}
	return node.validateTopology(entry)
}

func (node *Node) onPropose(payload Obj) (Obj, error) {
	given, _ := payload["entry"].(Obj)
	if given == nil {
		return nil, refuse("no entry")
	}
	proposal := core(given)
	if err := node.shape(proposal); err != nil {
		return nil, err
	}
	if err := node.validate(proposal); err != nil {
		return nil, err
	}
	if err := node.lock(proposal); err != nil {
		return nil, err
	}
	return Obj{"sig": SignEntry(node.cfg.Key, proposal), "slot": node.Slot()}, nil
}

func (node *Node) validateAdmit(entry Obj) error {
	body, _ := entry["body"].(Obj)
	nodeRecord, err := NodeRecord(body["node"])
	if err != nil {
		return refuse("%s", err.Error())
	}
	facts, factsOK := body["facts"].(Obj)
	if _, ok := nodeRecord["addr"].(string); !ok || !factsOK {
		return refuse("a join carries an address and facts")
	}
	node.mu.Lock()
	for _, member := range node.Log.Active() {
		if member.SignPub() == str(nodeRecord, "sign_pub") || str(member.Node, "ek_hash") == str(nodeRecord, "ek_hash") {
			node.mu.Unlock()
			return refuse("node is already a member")
		}
	}
	topology := node.topology
	var held [][]string
	for _, member := range node.Log.Active() {
		held = append(held, member.Roles)
	}
	node.mu.Unlock()
	claimed, _ := body["topology"].(Obj)
	if integer(claimed, "version") != topology.Version || str(claimed, "digest") != topology.Digest {
		return refuse("another topology is in force here")
	}
	expected := topology.SelectRoles(facts, held)
	if !equalStrings(stringList(body["roles"]), expected) {
		return refuse("roles should be %v", expected)
	}
	if len(expected) == 0 && topology.Unmatched == "refuse" {
		return refuse("no role matches this node")
	}
	pcrs, err := node.attestJoiner(nodeRecord)
	if err != nil {
		return err
	}
	image, err := node.Policy().Check(pcrs)
	if err != nil {
		return refuse("%s", err.Error())
	}
	policy, _ := body["policy"].(Obj)
	if str(policy, "image") != image || str(body, "pcr1") != pcrs["1"] {
		return refuse("the entry does not describe what the node reports")
	}
	return nil
}

func (node *Node) attestJoiner(record Obj) (map[string]string, error) {
	prover := node.cfg.Transport.Prover(str(record, "addr"), str(record, "tls_fp"))
	pcrs, err := Attest(prover, node.cfg.Verifier, str(record, "ek_hash"), NewNonce(), str(record, "sign_pub"), str(record, "tls_fp"))
	if err != nil {
		return nil, refuse("attestation failed: %s", err.Error())
	}
	return pcrs, nil
}

func (node *Node) validateEvict(entry Obj) error {
	slot, _ := asInt(entry["body"].(Obj)["slot"])
	node.mu.Lock()
	target := node.Log.Member(slot)
	var copied Member
	if target != nil {
		copied = *target
	}
	observer := node.observer
	node.mu.Unlock()
	if target == nil {
		return refuse("not an active member")
	}
	if observer == nil || observer.Healthy(&copied) {
		return refuse("this member sees it as healthy")
	}
	return nil
}

func (node *Node) validateTopology(entry Obj) error {
	body := entry["body"].(Obj)
	node.mu.Lock()
	topology := node.topology
	current := node.Log.TopologyVersion()
	node.mu.Unlock()
	if integer(body, "version") != topology.Version || str(body, "digest") != topology.Digest {
		return refuse("this is not the topology in force here")
	}
	if integer(body, "version") <= current {
		return refuse("topology version must be above %d", current)
	}
	return nil
}

func (node *Node) driveEntry(entry Obj) (Obj, error) {
	proposal := core(entry)
	signatures := Obj{}
	own, err := node.signAfterCheck(proposal)
	if err != nil {
		var refused *Refused
		if errors.As(err, &refused) && refused.Pending != nil {
			node.finish(refused.Pending)
			return nil, errSuperseded
		}
		return nil, err
	}
	signatures[strconv.Itoa(node.Slot())] = own
	node.mu.Lock()
	needed := Quorum(len(node.Log.Active()))
	node.mu.Unlock()
	excluded := -1
	if str(proposal, "type") == "evict" {
		excluded = integer(proposal["body"].(Obj), "slot")
	}
	for _, peer := range node.peers() {
		if len(signatures) >= needed {
			break
		}
		if peer.Slot == excluded {
			continue
		}
		reply, err := node.call(peer, "propose", Obj{"entry": proposal})
		if err != nil {
			var refused *Refused
			if errors.As(err, &refused) && refused.Pending != nil {
				node.finish(refused.Pending)
				return nil, errSuperseded
			}
			continue
		}
		signatures[strconv.Itoa(peer.Slot)] = str(reply, "sig")
	}
	if len(signatures) < needed {
		return nil, refuse("%d of %d signatures", len(signatures), needed)
	}
	signed := Obj{"index": proposal["index"], "prev": proposal["prev"], "type": proposal["type"], "body": proposal["body"], "sigs": signatures}
	if err := node.Commit(signed); err != nil {
		return nil, err
	}
	return signed, nil
}

func (node *Node) signAfterCheck(proposal Obj) (string, error) {
	if err := node.shape(proposal); err != nil {
		return "", err
	}
	if err := node.validate(proposal); err != nil {
		return "", err
	}
	if err := node.lock(proposal); err != nil {
		return "", err
	}
	return SignEntry(node.cfg.Key, proposal), nil
}

func (node *Node) finish(pending Obj) {
	node.CatchUp()
	node.mu.Lock()
	length := node.Log.Len()
	node.mu.Unlock()
	if index, _ := asInt(pending["index"]); index < length {
		return
	}
	_, _ = node.driveEntry(pending)
}

func (node *Node) Commit(entry Obj) error {
	if node.beforeCommit != nil {
		if err := node.beforeCommit(entry); err != nil {
			return err
		}
	}
	audience := node.peers()
	if err := node.Accept(entry); err != nil {
		return err
	}
	for _, peer := range audience {
		_, _ = node.call(peer, "commit", Obj{"entry": entry})
	}
	if str(entry, "type") == "admit" {
		if joiner := str(object(entry, "body")["node"].(Obj), "addr"); joiner != "" {
			_, _ = node.cfg.Transport.Call(joiner, "commit", Obj{"entry": entry})
		}
	}
	return nil
}

func (node *Node) run(kind string, body Obj) (Obj, error) {
	for round := 0; round < MaxRounds; round++ {
		node.CatchUp()
		node.mu.Lock()
		entry := Obj{"index": node.Log.Len(), "prev": node.Log.Head(), "type": kind, "body": body}
		node.mu.Unlock()
		signed, err := node.driveEntry(entry)
		if errors.Is(err, errSuperseded) {
			continue
		}
		return signed, err
	}
	return nil, refuse("too many competing entries")
}

func (node *Node) onJoin(payload Obj) (Obj, error) {
	record, _ := payload["node"].(Obj)
	facts, _ := payload["facts"].(Obj)
	if record == nil || facts == nil {
		return nil, refuse("a join carries a node record and facts")
	}
	if _, err := NodeRecord(record); err != nil {
		return nil, refuse("%s", err.Error())
	}
	pcrs, err := node.attestJoiner(record)
	if err != nil {
		return nil, err
	}
	image, err := node.Policy().Check(pcrs)
	if err != nil {
		return nil, refuse("%s", err.Error())
	}
	node.mu.Lock()
	topology := node.topology
	var held [][]string
	for _, member := range node.Log.Active() {
		held = append(held, member.Roles)
	}
	sponsor := node.slotLocked()
	node.mu.Unlock()
	body := Obj{
		"node": record, "roles": toAny(topology.SelectRoles(facts, held)), "facts": facts,
		"topology": Obj{"version": topology.Version, "digest": topology.Digest}, "policy": Obj{"image": image},
		"pcr1": pcrs["1"], "sponsor": sponsor,
	}
	entry, err := node.run("admit", body)
	if err != nil {
		return nil, err
	}
	return Obj{"entry": entry}, nil
}

func (node *Node) ProposeEvict(slot int, reason string) (Obj, error) {
	return node.run("evict", Obj{"slot": slot, "reason": reason})
}

func (node *Node) ProposeTopology() (Obj, error) {
	topology := node.Topology()
	return node.run("topology", Obj{"version": topology.Version, "digest": topology.Digest})
}

func sortedSlots(members []*Member) []int {
	slots := make([]int, len(members))
	for index, member := range members {
		slots[index] = member.Slot
	}
	sort.Ints(slots)
	return slots
}
