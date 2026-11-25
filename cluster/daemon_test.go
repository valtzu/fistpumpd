package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"testing"
	"time"
)

type recordingHost struct {
	mutex sync.Mutex
	calls [][]string
}

func (h *recordingHost) Run(name string, arguments ...string) {
	h.mutex.Lock()
	h.calls = append(h.calls, append([]string{name}, arguments...))
	h.mutex.Unlock()
}

func freeUDPPort(t testing.TB) int {
	t.Helper()
	for attempt := 0; attempt < 200; attempt++ {
		port := 20000 + rand.Intn(10000)
		connection, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			connection.Close()
			return port
		}
	}
	t.Fatal("no free port below the ephemeral range")
	return 0
}

var rigTopology = Obj{
	"version": 1,
	"roles": []any{
		Obj{"name": "server", "selector": Obj{"memory-gib": ">=4"}, "min": 3, "max": 3, "conflicts": []any{"agent"}},
		Obj{"name": "agent", "selector": Obj{}, "conflicts": []any{"server"}},
		Obj{"name": "ingress", "selector": Obj{}},
	},
	"vips": Obj{"server": []any{"10.9.0.20", "10.9.0.21", "10.9.0.22"}, "ingress": []any{"10.9.0.30"}},
}

func withFiles(t testing.TB, document Obj) Obj {
	copied := Obj{}
	for key, value := range document {
		copied[key] = value
	}
	copied["files"] = vectors(t)["apply"].(Obj)["files"]
	return copied
}

type rig struct {
	t        *testing.T
	dir      string
	tcp      []int
	udp      []int
	daemons  []*Daemon
	cancels  []context.CancelFunc
	done     []chan struct{}
	hosts    []*recordingHost
	document Obj
	tpmFor   func(index int) Prover
	verifier Verifier
}

func newRig(t *testing.T, count int) *rig {
	t.Setenv("FISTPUMPD_NO_SEAL", "1")
	r := &rig{t: t, dir: t.TempDir(), document: policyDocument(), verifier: FakeVerifier{}}
	for index := 0; index < count; index++ {
		r.tcp = append(r.tcp, freePort(t))
		r.udp = append(r.udp, freeUDPPort(t))
		r.hosts = append(r.hosts, &recordingHost{})
	}
	r.daemons, r.cancels, r.done = make([]*Daemon, count), make([]context.CancelFunc, count), make([]chan struct{}, count)
	t.Cleanup(r.stop)
	return r
}

func (r *rig) start(index int, pcrs map[string]string) *Daemon {
	r.t.Helper()
	root := filepath.Join(r.dir, fmt.Sprintf("n%d", index))
	for _, name := range []string{"state", "run", "root", "credstore"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
			r.t.Fatal(err)
		}
	}
	data, _ := json.Marshal(withFiles(r.t, rigTopology))
	_ = os.WriteFile(filepath.Join(root, "topology.json"), data, 0o644)
	genesis, err := ParseGenesis(Obj{"min_members": 2, "founder_wait": 1, "attest_interval": 1, "evict_after": 2, "join_retry": 1,
		"port": r.tcp[index], "discovery_port": r.udp[index]})
	if err != nil {
		r.t.Fatal(err)
	}
	var targets []Target
	for other, port := range r.udp {
		if other != index {
			targets = append(targets, Target{"127.0.0.1", port})
		}
	}
	var tpm Prover = NewFakeTPM(goodPCRs)
	if pcrs != nil {
		tpm = NewFakeTPM(pcrs)
	}
	if r.tpmFor != nil {
		tpm = r.tpmFor(index)
	}
	daemon, err := NewDaemon(DaemonConfig{
		Paths:   Paths{State: filepath.Join(root, "state"), Run: filepath.Join(root, "run"), Topology: filepath.Join(root, "topology.json"), Root: filepath.Join(root, "root"), Credstore: filepath.Join(root, "credstore")},
		Genesis: genesis, TPM: tpm, Verifier: r.verifier, Address: fmt.Sprintf("127.0.0.1:%d", r.tcp[index]), Facts: bigFacts, Host: r.hosts[index],
		Targets: targets, PolicyLoader: func() (Obj, error) { return r.document, nil }, Interface: "eth0",
	})
	if err != nil {
		r.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := daemon.Run(ctx); err != nil {
			r.t.Logf("daemon %d: %v", index, err)
		}
	}()
	r.daemons[index], r.cancels[index], r.done[index] = daemon, cancel, done
	return daemon
}

func (r *rig) stopOne(index int) {
	if r.daemons[index] == nil {
		return
	}
	r.cancels[index]()
	r.daemons[index].Stop()
	<-r.done[index]
	r.daemons[index] = nil
}

func (r *rig) stop() {
	for index := range r.daemons {
		r.stopOne(index)
	}
}

func (r *rig) wait(condition func() bool, seconds int) bool {
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func memberCount(d *Daemon) int {
	if d == nil || d.Node() == nil {
		return -1
	}
	_, _, length, _ := d.Node().Snapshot()
	return length
}

func TestThreeNodesFormAClusterWithoutAServer(t *testing.T) {
	r := newRig(t, 3)
	r.start(0, nil)
	if !r.wait(func() bool { return r.daemons[0].Node() != nil }, 30) {
		t.Fatal("the first node never founded")
	}
	if r.daemons[0].Node().Slot() != 0 {
		t.Fatal("the founder is slot 0")
	}
	if _, err := os.Stat(filepath.Join(r.dir, "n0/run/k3s-ready")); err == nil {
		t.Fatal("a lone node must not start k3s")
	}
	r.start(1, nil)
	r.start(2, nil)
	if !r.wait(func() bool {
		return memberCount(r.daemons[0]) == 3 && memberCount(r.daemons[1]) == 3 && memberCount(r.daemons[2]) == 3
	}, 60) {
		t.Fatal("the cluster did not form")
	}
	heads := map[string]bool{}
	for _, d := range r.daemons {
		_, head, _, _ := d.Node().Snapshot()
		heads[head] = true
	}
	if len(heads) != 1 {
		t.Fatal("heads differ")
	}
	ready := func() bool {
		for index := range r.daemons {
			if _, err := os.Stat(filepath.Join(r.dir, fmt.Sprintf("n%d/run/k3s-ready", index))); err != nil {
				return false
			}
		}
		return true
	}
	if !r.wait(ready, 30) {
		t.Fatal("k3s was not released")
	}
	first, _ := os.ReadFile(filepath.Join(r.dir, "n0/root/etc/rancher/k3s/config.yaml.d/10-role.yaml"))
	second, _ := os.ReadFile(filepath.Join(r.dir, "n1/root/etc/rancher/k3s/config.yaml.d/10-role.yaml"))
	if !regexp.MustCompile(`cluster-init: true`).Match(first) || !regexp.MustCompile(`server: https://10.9.0.20:6443`).Match(second) {
		t.Fatalf("k3s config:\n%s\n--\n%s", first, second)
	}
	tokens := func() bool {
		want := r.daemons[0].TokensStore().Get("server")
		for _, d := range r.daemons {
			if want == "" || d.TokensStore().Get("server") != want {
				return false
			}
		}
		return true
	}
	if !r.wait(tokens, 30) {
		t.Fatal("tokens did not reach every server")
	}
	best := map[string][2]int{}
	pattern := regexp.MustCompile(`(?s)vrrp_instance (SERVER\d) \{.*?priority (\d+)`)
	for _, d := range r.daemons {
		text, _ := os.ReadFile(filepath.Join(d.cfg.Paths.Run, "keepalived.conf"))
		for _, match := range pattern.FindAllStringSubmatch(string(text), -1) {
			var priority int
			fmt.Sscan(match[2], &priority)
			if priority > best[match[1]][0] {
				best[match[1]] = [2]int{priority, d.Node().Slot()}
			}
		}
	}
	var winners []int
	for _, entry := range best {
		winners = append(winners, entry[1])
	}
	sort.Ints(winners)
	if len(winners) != 3 || winners[0] != 0 || winners[1] != 1 || winners[2] != 2 {
		t.Fatalf("VIP winners %v", winners)
	}
}

func TestTwoNodesBootingTogetherFoundOneCluster(t *testing.T) {
	r := newRig(t, 2)
	r.start(0, nil)
	r.start(1, nil)
	if !r.wait(func() bool { return memberCount(r.daemons[0]) == 2 && memberCount(r.daemons[1]) == 2 }, 60) {
		t.Fatal("two nodes did not form one cluster")
	}
	_, a, _, _ := r.daemons[0].Node().Snapshot()
	_, b, _, _ := r.daemons[1].Node().Snapshot()
	if a != b {
		t.Fatal("two logs")
	}
}

func TestANodeWithUnknownFirmwareStaysOut(t *testing.T) {
	r := newRig(t, 2)
	r.start(0, nil)
	if !r.wait(func() bool { return r.daemons[0].Node() != nil }, 30) {
		t.Fatal("no founder")
	}
	bad := map[string]string{}
	for key, value := range goodPCRs {
		bad[key] = value
	}
	bad["11"] = repeat("9")
	r.start(1, bad)
	time.Sleep(8 * time.Second)
	if r.daemons[1].Node() != nil || memberCount(r.daemons[0]) != 1 {
		t.Fatal("the node must stay out")
	}
	if status := r.daemons[1].Handle; status == nil {
		t.Fatal("no handler")
	}
	reply, _ := r.daemons[1].Handle("status", Obj{})
	if got := fmt.Sprint(reply["status"]); !regexp.MustCompile(`PCR 11`).MatchString(got) {
		t.Fatalf("status %v", got)
	}
}

func TestARestartKeepsMembership(t *testing.T) {
	r := newRig(t, 2)
	r.start(0, nil)
	r.start(1, nil)
	if !r.wait(func() bool { return memberCount(r.daemons[0]) == 2 && memberCount(r.daemons[1]) == 2 }, 60) {
		t.Fatal("no cluster")
	}
	_, head, _, _ := r.daemons[1].Node().Snapshot()
	slot := r.daemons[1].Node().Slot()
	r.stopOne(1)
	replacement := r.start(1, nil)
	if !r.wait(func() bool { return replacement.Node() != nil }, 30) {
		t.Fatal("the node did not come back")
	}
	_, again, _, _ := replacement.Node().Snapshot()
	if again != head || replacement.Node().Slot() != slot {
		t.Fatalf("slot %d head %s", replacement.Node().Slot(), again)
	}
}

func TestANewTopologyIsAdoptedThroughTheLog(t *testing.T) {
	r := newRig(t, 2)
	r.start(0, nil)
	r.start(1, nil)
	if !r.wait(func() bool { return memberCount(r.daemons[0]) == 2 && memberCount(r.daemons[1]) == 2 }, 60) {
		t.Fatal("no cluster")
	}
	newer := Obj{}
	for key, value := range withFiles(t, rigTopology) {
		newer[key] = value
	}
	newer["version"] = 2
	newer["roles"] = []any{Obj{"name": "server", "selector": Obj{}, "max": 5}, Obj{"name": "agent", "selector": Obj{}, "conflicts": []any{"server"}}}
	data, _ := json.Marshal(newer)
	for _, d := range r.daemons {
		_ = os.WriteFile(d.cfg.Paths.Topology, data, 0o644)
	}
	adopted := func() bool {
		for _, d := range r.daemons {
			if _, _, _, version := d.Node().Snapshot(); version != 2 {
				return false
			}
		}
		return true
	}
	if !r.wait(adopted, 40) {
		t.Fatal("the topology was not adopted")
	}
}

func TestATopologyNobodyAgreedToIsNotRendered(t *testing.T) {
	r := newRig(t, 2)
	r.start(0, nil)
	r.start(1, nil)
	if !r.wait(func() bool { return memberCount(r.daemons[0]) == 2 && memberCount(r.daemons[1]) == 2 }, 60) {
		t.Fatal("no cluster")
	}
	newer := Obj{}
	for key, value := range withFiles(t, rigTopology) {
		newer[key] = value
	}
	newer["version"] = 2
	data, _ := json.Marshal(newer)
	lone := r.daemons[0]
	_ = os.WriteFile(lone.cfg.Paths.Topology, data, 0o644)
	if !r.wait(func() bool { return lone.currentTopology().Version == 2 }, 40) {
		t.Fatal("the node did not read the new file")
	}
	var rendered *Topology
	local := lone.Node().Topology()
	lone.Node().WithLog(func(chain *Chain) { rendered = lone.agreedTopology(chain, local) })
	if rendered.Version != 1 {
		t.Fatalf("topology v%d is rendered without agreement", rendered.Version)
	}
}
