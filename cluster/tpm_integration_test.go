//go:build swtpm

package cluster

import (
	"fmt"
	"os/exec"
	"testing"
	"time"
)

var zero = repeat("0")

func startSwtpm(t *testing.T, data int) {
	t.Helper()
	command := exec.Command("swtpm", "socket", "--tpmstate", "dir="+t.TempDir(), "--tpm2", "--ctrl", fmt.Sprintf("type=tcp,port=%d", data+1),
		"--server", fmt.Sprintf("type=tcp,port=%d", data), "--flags", "not-need-init,startup-clear")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
}

func TestSwtpmAttestationRoundTrip(t *testing.T) {
	startSwtpm(t, 2321)
	time.Sleep(1500 * time.Millisecond)
	prover := &TPMProver{Environment: []string{"TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321"}}
	hello, err := prover.Hello()
	if err != nil {
		t.Fatal(err)
	}
	ek, _ := EKHash(hello)
	nonce := NewNonce()
	pcrs, err := Attest(prover, TPMVerifier{}, ek, nonce, repeat("ab"), repeat("cd"))
	if err != nil || len(pcrs) != 6 || len(pcrs["0"]) != 64 {
		t.Fatalf("%v %v", pcrs, err)
	}
	qualifying, _ := Binding(nonce, repeat("ab"), repeat("cd"))
	quote, err := prover.Quote(qualifying)
	if err != nil {
		t.Fatal(err)
	}
	forged := quote["pcrs"].(Obj)
	forged["7"] = repeat("11")
	if _, err := (TPMVerifier{}).CheckQuote(hello, quote, qualifying); err == nil {
		t.Fatal("a forged PCR must be detected")
	}
	quote, _ = prover.Quote("00" + qualifying[2:])
	if _, err := (TPMVerifier{}).CheckQuote(hello, quote, qualifying); err == nil {
		t.Fatal("a wrong nonce must be detected")
	}
}

func TestClusterFormsWithRealAttestation(t *testing.T) {
	ports := []int{2341, 2351, 2361}
	for _, port := range ports {
		startSwtpm(t, port)
	}
	time.Sleep(2 * time.Second)
	r := newRig(t, 3)
	r.verifier = TPMVerifier{}
	r.document = Obj{
		"firmware":             []any{Obj{"pcr0": zero}},
		"secure_boot":          Obj{"pcr7": zero},
		"versions":             []any{Obj{"version": "1", "pcr11": zero, "channel": "canary"}},
		"peripheral_firmware":  []any{Obj{"pcr2": zero}},
		"eeprom_configuration": []any{Obj{"pcr3": zero}},
	}
	r.tpmFor = func(index int) Prover {
		return &TPMProver{Environment: []string{fmt.Sprintf("TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=%d", ports[index])}}
	}
	r.start(0, nil)
	if !r.wait(func() bool { return r.daemons[0].Node() != nil }, 120) {
		t.Fatal("no founder")
	}
	r.start(1, nil)
	if !r.wait(func() bool { return r.daemons[1].Node() != nil }, 180) {
		t.Fatal("the second node was not admitted")
	}
	r.start(2, nil)
	if !r.wait(func() bool { return memberCount(r.daemons[2]) == 3 }, 240) {
		t.Fatal("the third node was not admitted")
	}
	keys := map[string]bool{}
	for _, member := range mustActive(r.daemons[0].Node()) {
		keys[str(member.Node, "ek_hash")] = true
	}
	if len(keys) != 3 {
		t.Fatal("three distinct endorsement keys expected")
	}
}
