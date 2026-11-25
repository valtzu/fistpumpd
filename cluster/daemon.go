package cluster

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

const (
	policyMaxAge         = 3600 * time.Second
	policyRefusalRefresh = 15 * time.Second
)

type Paths struct {
	State      string
	Run        string
	Topology   string
	Topologies []string
	Root       string
	Credstore  string
}

type DaemonConfig struct {
	Paths            Paths
	Genesis          *Genesis
	TPM              Prover
	Verifier         Verifier
	Address          string
	Facts            Obj
	Host             Host
	Targets          []Target
	BuildCertificate []byte
	PolicyLoader     func() (Obj, error)
	Interface        string
	Seal             bool
}

type Daemon struct {
	cfg        DaemonConfig
	key        ed25519.PrivateKey
	record     Obj
	tlsKey     string
	tlsCert    string
	store      *DirStore
	tokens     *Tokens
	transport  *HTTPSTransport
	front      *Switch
	mutex      sync.Mutex
	node       *Node
	policy     *Policy
	policyTime time.Time
	policyErr  string
	topology   *Topology
	failing    map[int]time.Time
	pcr1Noted  map[int]string
	status     Obj
	settings   *View
	servers    []interface{ Stop() }
	serving    bool
	apply      sync.Mutex
	facts      Obj
}

func NewDaemon(cfg DaemonConfig) (*Daemon, error) {
	daemon := &Daemon{cfg: cfg, front: &Switch{}, failing: map[int]time.Time{}, status: Obj{"phase": "starting"}}
	var err error
	if daemon.key, err = LoadKey(filepath.Join(cfg.Paths.State, "identity")); err != nil {
		return nil, err
	}
	var fingerprint string
	if daemon.tlsKey, daemon.tlsCert, fingerprint, err = CreateTLS(filepath.Join(cfg.Paths.State, "identity")); err != nil {
		return nil, err
	}
	hello, err := cfg.TPM.Hello()
	if err != nil {
		return nil, err
	}
	ek, err := EKHash(hello)
	if err != nil {
		return nil, err
	}
	daemon.record = Obj{"sign_pub": PublicHex(daemon.key), "tls_fp": fingerprint, "ek_hash": ek, "addr": cfg.Address}
	if daemon.store, err = NewDirStore(filepath.Join(cfg.Paths.State, "log")); err != nil {
		return nil, err
	}
	if daemon.tokens, err = NewTokens(filepath.Join(cfg.Paths.State, "tokens"), cfg.Paths.Credstore, cfg.Seal); err != nil {
		return nil, err
	}
	daemon.transport = &HTTPSTransport{Pins: daemon.pin}
	daemon.facts = cfg.Facts
	if daemon.facts == nil {
		daemon.facts = CollectFacts("/")
	}
	if cfg.Host == nil {
		daemon.cfg.Host = SystemHost{}
	}
	return daemon, nil
}

func (d *Daemon) pin(address string) string {
	d.mutex.Lock()
	node := d.node
	d.mutex.Unlock()
	if node == nil {
		return ""
	}
	pin := ""
	node.WithLog(func(chain *Chain) {
		for _, member := range chain.Active() {
			if member.Addr() == address {
				pin = str(member.Node, "tls_fp")
			}
		}
	})
	return pin
}

func (d *Daemon) setStatus(status Obj) {
	d.mutex.Lock()
	d.status = status
	d.mutex.Unlock()
}

func (d *Daemon) Node() *Node {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.node
}

func (d *Daemon) topologyPath() string {
	for _, path := range d.cfg.Paths.Topologies {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return d.cfg.Paths.Topology
}

func (d *Daemon) loadTopology() error {
	data, err := os.ReadFile(d.topologyPath())
	if err != nil {
		return err
	}
	document, err := DecodeObj(data)
	if err != nil {
		return err
	}
	topology, err := ParseTopology(document)
	if err != nil {
		return err
	}
	d.mutex.Lock()
	d.topology = topology
	d.mutex.Unlock()
	return nil
}

func (d *Daemon) currentTopology() *Topology {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.topology
}

func (d *Daemon) currentPolicy() *Policy {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.policy
}

func (d *Daemon) refreshPolicyAfterRefusal() *Policy {
	d.mutex.Lock()
	recent := time.Since(d.policyTime) < policyRefusalRefresh
	current := d.policy
	d.mutex.Unlock()
	if recent {
		return current
	}
	return d.loadPolicy(true)
}

func (d *Daemon) loadPolicy(force bool) *Policy {
	d.mutex.Lock()
	fresh := d.policy != nil && !force && time.Since(d.policyTime) < policyMaxAge
	current := d.policy
	d.mutex.Unlock()
	if fresh {
		return current
	}
	document, err := d.cfg.PolicyLoader()
	d.mutex.Lock()
	if err != nil {
		d.policyErr = err.Error()
		log.Printf("policy refresh failed: %v", err)
		if d.policy == nil {
			d.policy = NewPolicy(Obj{})
		}
	} else {
		d.policy, d.policyTime, d.policyErr = NewPolicy(document), time.Now(), ""
	}
	current, node := d.policy, d.node
	d.mutex.Unlock()
	if node != nil {
		node.SetPolicy(current)
	}
	return current
}

type observer struct{ daemon *Daemon }

func (o observer) Healthy(member *Member) bool { return o.daemon.attestMember(member) }

func (d *Daemon) nodeConfig() Config {
	return Config{
		Key: d.key, Record: d.record, Facts: d.facts, Store: d.store, Topology: d.currentTopology(), Policy: d.currentPolicy(),
		Verifier: d.cfg.Verifier, Transport: d.transport, BuildCertificate: d.cfg.BuildCertificate, Observer: observer{d},
		OnChange: d.changed, TPM: d.cfg.TPM, Tokens: d.tokens, PolicyRefresh: d.refreshPolicyAfterRefusal,
	}
}

func (d *Daemon) info() Obj {
	d.mutex.Lock()
	node := d.node
	d.mutex.Unlock()
	info := Obj{"role": "candidate", "addr": d.cfg.Address, "ek_hash": str(d.record, "ek_hash"), "genesis": nil, "length": 0}
	if node != nil {
		node.WithLog(func(chain *Chain) {
			info["role"], info["length"] = "member", chain.Len()
			if chain.Len() > 0 {
				info["genesis"] = EntryHash(chain.Entries[0])
			}
		})
	}
	return info
}

func (d *Daemon) serve(target Handler) error {
	d.front.Set(target)
	if d.serving {
		return nil
	}
	d.serving = true
	host, port, err := net.SplitHostPort(d.cfg.Address)
	if err != nil {
		return err
	}
	bind := ":" + port
	discoveryBind := "0.0.0.0"
	if host == "127.0.0.1" || host == "::1" {
		bind, discoveryBind = d.cfg.Address, host
	}
	server, err := StartServer(d.front, bind, d.tlsCert, d.tlsKey)
	if err != nil {
		return err
	}
	d.servers = append(d.servers, server)
	responder, err := StartResponder(d.cfg.Genesis.DiscoveryPort, discoveryBind, d.info)
	if err != nil {
		return err
	}
	d.servers = append(d.servers, responder)
	return d.startAPI(host)
}

func (d *Daemon) startAPI(host string) error {
	if d.cfg.Genesis.APIPort <= 0 {
		return nil
	}
	if !anyReadable(d.cfg.Genesis.APIClientCAs) {
		return nil
	}
	bind := fmt.Sprintf(":%d", d.cfg.Genesis.APIPort)
	if host == "127.0.0.1" || host == "::1" {
		bind = net.JoinHostPort(host, strconv.Itoa(d.cfg.Genesis.APIPort))
	}
	server, err := StartKubeAPI(NewKubeAPI(d.apiSnapshot), bind, d.tlsCert, d.tlsKey, d.cfg.Genesis.APIClientCAs)
	if err != nil {
		log.Printf("read API: %v", err)
		return nil
	}
	d.servers = append(d.servers, server)
	return nil
}

func (d *Daemon) apiSnapshot() APISnapshot {
	node := d.Node()
	if node == nil {
		return APISnapshot{}
	}
	active, _, _, version := node.Snapshot()
	d.mutex.Lock()
	failing := map[int]time.Time{}
	for slot, since := range d.failing {
		failing[slot] = since
	}
	topology := d.topology
	d.mutex.Unlock()
	snapshot := APISnapshot{Topology: version, Roles: roleStatus(topology, active, failing)}
	for _, member := range active {
		_, bad := failing[member.Slot]
		snapshot.Members = append(snapshot.Members, APIMember{
			Slot: member.Slot, Number: member.Number, Addr: member.Addr(), Roles: member.Roles, Facts: member.Facts,
			Image: str(member.Policy, "image"), Healthy: !bad,
		})
	}
	return snapshot
}

func (d *Daemon) become(node *Node) error {
	node.SetObserver(observer{d})
	node.SetOnChange(d.changed)
	node.SetTokens(d.tokens)
	node.SetTPM(d.cfg.TPM)
	d.mutex.Lock()
	d.node = node
	d.mutex.Unlock()
	if err := d.serve(node); err != nil {
		return err
	}
	d.setStatus(Obj{"phase": "member", "slot": node.Slot()})
	d.changed(node)
	return nil
}

func (d *Daemon) startMember() (*Node, error) {
	lines, err := d.store.LoadLines()
	if err != nil || len(lines) == 0 {
		return nil, err
	}
	node, err := Restore(d.nodeConfig())
	if err != nil {
		return nil, err
	}
	if node.Slot() < 0 {
		d.setStatus(Obj{"phase": "evicted"})
		return nil, nil
	}
	return node, nil
}

func (d *Daemon) discoveryBind() string {
	if host, _, _ := net.SplitHostPort(d.cfg.Address); host == "127.0.0.1" {
		return "127.0.0.1"
	}
	return "0.0.0.0"
}

func (d *Daemon) joinOrFound(ctx context.Context) (*Node, error) {
	candidate := NewCandidate(d.nodeConfig())
	if err := d.serve(candidate); err != nil {
		return nil, err
	}
	started := time.Now()
	for ctx.Err() == nil {
		d.loadPolicy(false)
		replies := Probe(d.cfg.Targets, 3*time.Second, d.discoveryBind())
		var seeds []string
		var others []string
		for _, reply := range replies {
			switch str(reply, "role") {
			case "member":
				seeds = append(seeds, str(reply, "addr"))
			case "candidate":
				if str(reply, "addr") != d.cfg.Address {
					others = append(others, str(reply, "ek_hash"))
				}
			}
		}
		seeds = append(seeds, d.cfg.Genesis.Seeds...)
		if len(seeds) > 0 {
			node, err := NewCandidate(d.nodeConfig()).Join(seeds)
			if err == nil {
				return node, nil
			}
			d.setStatus(Obj{"phase": "joining", "error": err.Error()})
			log.Printf("join refused: %v", err)
			if !sleep(ctx, d.cfg.Genesis.JoinRetry) {
				return nil, nil
			}
			continue
		}
		lowest := str(d.record, "ek_hash")
		for _, other := range others {
			if other < lowest {
				lowest = other
			}
		}
		if time.Since(started).Seconds() >= d.cfg.Genesis.FounderWait && lowest == str(d.record, "ek_hash") {
			log.Printf("no cluster found, founding one")
			return Found(d.nodeConfig())
		}
		d.setStatus(Obj{"phase": "waiting", "candidates": len(others)})
		if !sleep(ctx, 2) {
			return nil, nil
		}
	}
	return nil, nil
}

func sleep(ctx context.Context, seconds float64) bool {
	timer := time.NewTimer(time.Duration(seconds * float64(time.Second)))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (d *Daemon) attestMember(member *Member) bool {
	prover := d.transport.Prover(member.Addr(), str(member.Node, "tls_fp"))
	pcrs, err := Attest(prover, d.cfg.Verifier, str(member.Node, "ek_hash"), NewNonce(), member.SignPub(), str(member.Node, "tls_fp"))
	if err == nil {
		if _, err = d.loadPolicy(false).Check(pcrs); err != nil {
			_, err = d.refreshPolicyAfterRefusal().Check(pcrs)
		}
	}
	if err != nil {
		log.Printf("slot %d failed attestation: %v", member.Slot, err)
		return false
	}
	d.notePCR1(member, pcrs["1"])
	return true
}

func (d *Daemon) notePCR1(member *Member, current string) {
	if member.PCR1 == "" || member.PCR1 == current {
		return
	}
	d.mutex.Lock()
	defer d.mutex.Unlock()
	if d.pcr1Noted == nil {
		d.pcr1Noted = map[int]string{}
	}
	if d.pcr1Noted[member.Slot] == current {
		return
	}
	d.pcr1Noted[member.Slot] = current
	log.Printf("slot %d reports PCR 1 %s, its admission pinned %s: not enforced, the endorsement key already identifies the machine", member.Slot, current, member.PCR1)
}

func (d *Daemon) changed(node *Node) {
	d.apply.Lock()
	defer d.apply.Unlock()
	var plan *View
	evicted := false
	topology := node.Topology()
	node.WithLog(func(chain *Chain) {
		slot := chain.SlotOf(str(d.record, "sign_pub"))
		if slot < 0 {
			evicted = true
			return
		}
		plan = BuildView(chain, slot, topology, d.cfg.Genesis.MinMembers, d.cfg.Interface)
	})
	if evicted {
		d.setStatus(Obj{"phase": "evicted"})
		return
	}
	d.mutex.Lock()
	d.settings = plan
	d.mutex.Unlock()
	if plan.CreatesTokens {
		if err := d.tokens.Create(); err != nil {
			log.Printf("tokens: %v", err)
		}
	}
	for _, kind := range plan.NeedsTokens {
		if d.tokens.Get(kind) == "" {
			if value := node.FetchToken(kind); value != "" {
				_ = d.tokens.Put(kind, value)
			}
		}
	}
	wanted := []string{"agent"}
	if contains(plan.Roles, "server") {
		wanted = []string{"server", "agent"}
	}
	if err := d.tokens.InstallCredentials(wanted); err != nil {
		log.Printf("could not install credentials: %v", err)
	}
	if _, err := Apply(plan, topology.Files, d.root(), d.cfg.Paths.Run, d.cfg.Host); err != nil {
		log.Printf("apply: %v", err)
	}
}

func (d *Daemon) root() string {
	if d.cfg.Paths.Root == "" {
		return "/"
	}
	return d.cfg.Paths.Root
}

func (d *Daemon) housekeeping(ctx context.Context) {
	node := d.Node()
	node.CatchUp()
	if node.Slot() < 0 {
		d.setStatus(Obj{"phase": "evicted"})
		return
	}
	d.loadPolicy(false)
	d.reloadTopology(node)
	d.changed(node)
	d.adoptTopology(ctx, node)
	d.checkPeers(ctx, node)
	active, _, length, _ := node.Snapshot()
	d.mutex.Lock()
	policyErr := d.policyErr
	d.mutex.Unlock()
	d.setStatus(Obj{"phase": "member", "slot": node.Slot(), "members": len(active), "length": length, "policy_error": policyErr})
}

func (d *Daemon) reloadTopology(node *Node) {
	data, err := os.ReadFile(d.topologyPath())
	if err != nil {
		return
	}
	document, err := DecodeObj(data)
	if err != nil {
		return
	}
	newest, err := ParseTopology(document)
	if err != nil {
		log.Printf("topology not reloaded: %v", err)
		return
	}
	current := d.currentTopology()
	if newest.Version >= current.Version && newest.Digest != current.Digest {
		d.mutex.Lock()
		d.topology = newest
		d.mutex.Unlock()
		node.SetTopology(newest)
	}
}

func (d *Daemon) delayByRank(ctx context.Context, node *Node) {
	rank := 0
	node.WithLog(func(chain *Chain) { rank = chain.RankOf(chain.SlotOf(str(d.record, "sign_pub"))) })
	sleep(ctx, float64(rank)*2+rand.Float64())
}

func (d *Daemon) adoptTopology(ctx context.Context, node *Node) {
	_, _, _, version := node.Snapshot()
	if d.currentTopology().Version <= version {
		return
	}
	d.delayByRank(ctx, node)
	node.CatchUp()
	if _, _, _, version = node.Snapshot(); d.currentTopology().Version > version {
		if _, err := node.ProposeTopology(); err != nil {
			log.Printf("topology adoption not agreed yet: %v", err)
		}
	}
}

func (d *Daemon) checkPeers(ctx context.Context, node *Node) {
	now := time.Now()
	for _, peer := range node.peers() {
		d.mutex.Lock()
		d.mutex.Unlock()
		if d.attestMember(peer) {
			d.mutex.Lock()
			delete(d.failing, peer.Slot)
			d.mutex.Unlock()
		} else {
			d.mutex.Lock()
			if _, seen := d.failing[peer.Slot]; !seen {
				d.failing[peer.Slot] = now
			}
			d.mutex.Unlock()
		}
	}
	active, _, _, _ := node.Snapshot()
	alive := map[int]bool{}
	for _, member := range active {
		alive[member.Slot] = true
	}
	d.mutex.Lock()
	failing := map[int]time.Time{}
	for slot, since := range d.failing {
		if alive[slot] {
			failing[slot] = since
		} else {
			delete(d.failing, slot)
		}
	}
	d.mutex.Unlock()
	for slot, since := range failing {
		if now.Sub(since).Seconds() >= d.cfg.Genesis.EvictAfter {
			d.delayByRank(ctx, node)
			if _, err := node.ProposeEvict(slot, fmt.Sprintf("failed attestation for %d s", int(now.Sub(since).Seconds()))); err != nil {
				log.Printf("eviction of slot %d not agreed: %v", slot, err)
			}
		}
	}
}

func (d *Daemon) Handle(method string, payload Obj) (Obj, error) {
	node := d.Node()
	switch method {
	case "status":
		reply := Obj{"topology": d.currentTopology().Version, "slot": nil, "members": []any{}, "head": nil, "length": 0}
		d.mutex.Lock()
		reply["status"] = d.status
		failing := Obj{}
		for slot, since := range d.failing {
			failing[strconv.Itoa(slot)] = int(since.Unix())
		}
		reply["failing"] = failing
		d.mutex.Unlock()
		if node != nil {
			active, head, length, _ := node.Snapshot()
			members := []any{}
			for _, member := range active {
				members = append(members, Obj{"slot": member.Slot, "number": member.Number, "node": member.Node, "roles": toAny(member.Roles), "status": member.Status})
			}
			reply["slot"], reply["members"], reply["head"], reply["length"] = node.Slot(), members, head, length
			d.mutex.Lock()
			var listed []any
			for _, role := range roleStatus(d.topology, active, d.failing) {
				entry := Obj{"name": role.Name, "min": role.Min, "held": role.Held, "ready": role.Ready}
				if role.Max != nil {
					entry["max"] = *role.Max
				}
				listed = append(listed, entry)
			}
			reply["roles"] = listed
			d.mutex.Unlock()
		}
		return reply, nil
	case "log":
		if node == nil {
			return Obj{"entries": []any{}}, nil
		}
		return node.onLog(Obj{"from": 0}), nil
	case "evict":
		if node == nil {
			return nil, refuse("this node is not a member")
		}
		slot, _ := asInt(payload["slot"])
		reason := str(payload, "reason")
		if reason == "" {
			reason = "operator request"
		}
		entry, err := node.ProposeEvict(slot, reason)
		return Obj{"entry": entry}, err
	case "submit":
		if node == nil {
			return nil, refuse("this node is not a member")
		}
		entry, _ := payload["entry"].(Obj)
		if err := node.Commit(entry); err != nil {
			return nil, refuse("%s", err.Error())
		}
		_, _, length, _ := node.Snapshot()
		return Obj{"length": length}, nil
	}
	return nil, refuse("unknown control method %s", method)
}

func (d *Daemon) Run(ctx context.Context) error {
	control, err := StartControl(d, filepath.Join(d.cfg.Paths.Run, "control.sock"))
	if err != nil {
		return err
	}
	d.servers = append(d.servers, control)
	if err := d.loadTopology(); err != nil {
		return err
	}
	d.loadPolicy(true)
	node, err := d.startMember()
	if err != nil {
		return err
	}
	if node == nil && d.statusPhase() != "evicted" {
		if node, err = d.joinOrFound(ctx); err != nil {
			return err
		}
	}
	if node == nil {
		return nil
	}
	if node.Slot() < 0 {
		d.setStatus(Obj{"phase": "evicted"})
		return nil
	}
	if d.Node() == nil {
		if err := d.become(node); err != nil {
			return err
		}
	}
	for ctx.Err() == nil {
		d.housekeeping(ctx)
		if !sleep(ctx, d.cfg.Genesis.AttestEvery) {
			break
		}
	}
	return nil
}

func (d *Daemon) statusPhase() string {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return str(d.status, "phase")
}

func (d *Daemon) Stop() {
	for _, server := range d.servers {
		server.Stop()
	}
	d.servers = nil
}

func (d *Daemon) Settings() *View {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.settings
}

func (d *Daemon) TokensStore() *Tokens { return d.tokens }

func sortedKeys(values map[int]time.Time) []int {
	keys := make([]int, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	return keys
}

func roleStatus(topology *Topology, active []*Member, failing map[int]time.Time) []APIRole {
	var roles []APIRole
	for _, role := range topology.Roles {
		entry := APIRole{Name: role.Name, Min: role.Min, Max: role.Max}
		for _, member := range active {
			if !contains(member.Roles, role.Name) {
				continue
			}
			entry.Held++
			if _, bad := failing[member.Slot]; !bad {
				entry.Ready++
			}
		}
		roles = append(roles, entry)
	}
	return roles
}
