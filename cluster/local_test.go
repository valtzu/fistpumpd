package cluster

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func fakeRoot(t *testing.T, kib int, disks map[string]int, usrSource, model string) string {
	t.Helper()
	root := t.TempDir()
	write := func(path, content string) {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("proc/meminfo", fmt.Sprintf("MemTotal:       %d kB\n", kib))
	write("proc/device-tree/model", model+"\x00")
	write("proc/self/mountinfo", fmt.Sprintf("36 35 8:2 / /usr ro,relatime - ext4 %s ro\n", usrSource))
	for name, size := range disks {
		write(filepath.Join("sys/block", name, "size"), fmt.Sprint(size*1024*1024*1024/512))
	}
	write("dev/tpmrm0", "")
	return root
}

func TestFactsCollect(t *testing.T) {
	root := fakeRoot(t, 8*1024*1024, map[string]int{"mmcblk0": 32, "sda": 900}, "/dev/mmcblk0p2", "Raspberry Pi 4 Model B Rev 1.5")
	facts := CollectFacts(root)
	if facts["memory-gib"] != 8 || facts["disk-gib"] != 900 || facts["board"] != "raspberry-pi-4-model-b-rev-1-5" || facts["tpm"] != true {
		t.Fatalf("%v", facts)
	}
}

func TestTheRootDiskIsNotCountedAsData(t *testing.T) {
	facts := CollectFacts(fakeRoot(t, 4*1024*1024, map[string]int{"sda": 240}, "/dev/sda2", "Pi"))
	if facts["disk-gib"] != 0 {
		t.Fatalf("%v", facts)
	}
}

func TestVirtualDevicesAreIgnored(t *testing.T) {
	facts := CollectFacts(fakeRoot(t, 4*1024*1024, map[string]int{"mmcblk0": 32, "zram0": 4, "loop0": 1}, "/dev/mmcblk0p2", "Pi"))
	if facts["disk-gib"] != 0 {
		t.Fatalf("%v", facts)
	}
}

func TestGenesisRefusesALoneNode(t *testing.T) {
	if _, err := ParseGenesis(Obj{"min_members": 1}); err == nil {
		t.Fatal("a lone node is not a cluster")
	}
	if _, err := ParseGenesis(Obj{"policy_urls": []any{"http://x"}}); err == nil {
		t.Fatal("policy URLs are https")
	}
	if genesis, err := ParseGenesis(Obj{}); err != nil || genesis.MinMembers != 2 {
		t.Fatalf("%v", err)
	}
}

func TestIdentityKeyPersists(t *testing.T) {
	t.Setenv("FISTPUMPD_NO_SEAL", "1")
	directory := t.TempDir()
	first, err := LoadKey(directory)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := LoadKey(directory)
	if PublicHex(first) != PublicHex(second) {
		t.Fatal("the key changed")
	}
	info, _ := os.Stat(filepath.Join(directory, "sign.key"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode())
	}
}

func TestTLSIdentityIsStable(t *testing.T) {
	directory := t.TempDir()
	_, _, first, err := CreateTLS(directory)
	if err != nil {
		t.Fatal(err)
	}
	_, _, second, _ := CreateTLS(directory)
	if first != second || len(first) != 64 {
		t.Fatal("the certificate changed")
	}
}

func TestTokensAreCreatedOnceAndInstalled(t *testing.T) {
	t.Setenv("FISTPUMPD_NO_SEAL", "1")
	tokens, err := NewTokens(t.TempDir(), t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	_ = tokens.Create()
	server, agent := tokens.Get("server"), tokens.Get("agent")
	_ = tokens.Create()
	if server == "" || agent == "" || server == agent || tokens.Get("server") != server {
		t.Fatal("tokens must be distinct and stable")
	}
	if err := tokens.InstallCredentials([]string{"server", "agent"}); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(filepath.Join(tokens.Credstore, "k3s-agent.token")); strings.TrimSpace(string(data)) != agent {
		t.Fatal("the agent credential is wrong")
	}
}

type recording struct{ calls [][]string }

func (r *recording) Run(name string, arguments ...string) {
	r.calls = append(r.calls, append([]string{name}, arguments...))
}

func vectorChain(t *testing.T) (*Chain, *Topology) {
	chain := NewChain(nil)
	for _, entry := range vectors(t)["chain"].(Obj)["entries"].([]any) {
		if err := chain.Append(entry.(Obj)); err != nil {
			t.Fatal(err)
		}
	}
	topology, err := ParseTopology(vectors(t)["topology"].(Obj)["document"].(Obj))
	if err != nil {
		t.Fatal(err)
	}
	return chain, topology
}

func TestApplyWritesOnceAndSignalsOnlyOnChange(t *testing.T) {
	chain, topology := vectorChain(t)
	root, run := t.TempDir(), t.TempDir()
	host := &recording{}
	plan := BuildPlan(chain, 0, topology, 2, "eth0")
	if _, err := Apply(plan, root, run, host); err != nil {
		t.Fatal(err)
	}
	first := len(host.calls)
	want := [][]string{{"systemctl", "reload-or-restart", "keepalived.service"}, {"systemctl", "start", "--no-block", "k3s.service"}, {"hostnamectl", "tags", "ingress", "server"}}
	for _, expected := range want {
		found := false
		for _, call := range host.calls {
			found = found || strings.Join(call, " ") == strings.Join(expected, " ")
		}
		if !found && expected[0] != "hostnamectl" {
			t.Errorf("missing call %v in %v", expected, host.calls)
		}
	}
	if _, err := Apply(plan, root, run, host); err != nil || len(host.calls) != first {
		t.Fatalf("a second apply must not signal anything: %v", host.calls[first:])
	}
	if _, err := os.Stat(filepath.Join(root, "etc/rancher/k3s/config.yaml.d/10-role.yaml")); err != nil {
		t.Fatal(err)
	}
}

func TestApplyRemovesStaleRoleMarkers(t *testing.T) {
	chain, topology := vectorChain(t)
	root, run := t.TempDir(), t.TempDir()
	plan := BuildPlan(chain, 0, topology, 2, "eth0")
	_, _ = Apply(plan, root, run, &recording{})
	plan.Roles = []string{"agent"}
	_, _ = Apply(plan, root, run, &recording{})
	if _, err := os.Stat(filepath.Join(root, "etc/node-role.d/server.conf")); err == nil {
		t.Fatal("the server marker must go")
	}
	if _, err := os.Stat(filepath.Join(root, "etc/node-role.d/agent.conf")); err != nil {
		t.Fatal("the agent marker must exist")
	}
}

func signedPolicyBucket(t *testing.T) (Opener, string) {
	t.Helper()
	home := t.TempDir()
	gpg := func(input []byte, arguments ...string) []byte {
		command := exec.Command("gpg", append([]string{"--batch", "--passphrase", "", "--homedir", home}, arguments...)...)
		command.Stdin = strings.NewReader(string(input))
		output, err := command.Output()
		if err != nil {
			t.Skipf("gpg is not usable here: %v", err)
		}
		return output
	}
	gpg(nil, "--quick-generate-key", "updates@test", "default", "default", "never")
	keyring := filepath.Join(home, "ring.gpg")
	_ = os.WriteFile(keyring, gpg(nil, "--export", "updates@test"), 0o600)
	versions := []byte(`{"versions":[{"version":"1","pcr11":"` + repeat("a") + `"}],"secure_boot":{"pcr7":"` + repeat("b") + `"},"firmware":[{"pcr0":"` + repeat("c") + `"}]}`)
	sum := sha256.Sum256(versions)
	sums := []byte(hex.EncodeToString(sum[:]) + "  versions.json\n")
	files := map[string][]byte{"SHA256SUMS": sums, "SHA256SUMS.gpg": gpg(sums, "--detach-sign", "--local-user", "updates@test"), "versions.json": versions}
	return func(url string) ([]byte, error) {
		if data, ok := files[url[strings.LastIndex(url, "/")+1:]]; ok {
			return data, nil
		}
		return nil, fmt.Errorf("404")
	}, keyring
}

func TestASignedPolicyIsAccepted(t *testing.T) {
	open, keyring := signedPolicyBucket(t)
	document, err := FetchPolicy("https://x/canary", keyring, open)
	if err != nil || len(document["versions"].([]any)) != 1 {
		t.Fatalf("%v", err)
	}
}

func TestATamperedPolicyIsRefused(t *testing.T) {
	open, keyring := signedPolicyBucket(t)
	tampered := func(url string) ([]byte, error) {
		data, err := open(url)
		if strings.HasSuffix(url, "versions.json") {
			data = append(data, ' ')
		}
		return data, err
	}
	if _, err := FetchPolicy("https://x/c", keyring, tampered); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("%v", err)
	}
}

func TestTheCacheServesWhenTheBucketIsDown(t *testing.T) {
	open, keyring := signedPolicyBucket(t)
	cache := filepath.Join(t.TempDir(), "policy.json")
	if _, err := RefreshPolicy([]string{"https://x/c"}, keyring, cache, open); err != nil {
		t.Fatal(err)
	}
	down := func(string) ([]byte, error) { return nil, fmt.Errorf("down") }
	document, err := RefreshPolicy([]string{"https://x/c"}, keyring, cache, down)
	if err != nil || document["versions"].([]any)[0].(Obj)["pcr11"] != repeat("a") {
		t.Fatalf("%v", err)
	}
}

func TestMergedPolicyAcceptsBothChannels(t *testing.T) {
	merged := MergePolicies([]Obj{
		{"versions": []any{Obj{"pcr11": repeat("1")}}, "secure_boot": Obj{"pcr7": repeat("7")}, "firmware": []any{Obj{"pcr0": repeat("0")}}},
		{"versions": []any{Obj{"pcr11": repeat("2")}}, "secure_boot": Obj{"pcr7": repeat("7")}, "firmware": []any{Obj{"pcr0": repeat("0")}}},
	})
	policy := NewPolicy(merged)
	if !equalStrings(policy.Allowed[11], []string{repeat("1"), repeat("2")}) || !equalStrings(policy.Allowed[7], []string{repeat("7")}) {
		t.Fatalf("%v", policy.Allowed)
	}
}
