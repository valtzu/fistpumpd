//go:build swtpm

package cluster

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

var zero = repeat("0")

func startSwtpm(t *testing.T, data int) []string {
	t.Helper()
	command := exec.Command("swtpm", "socket", "--tpmstate", "dir="+t.TempDir(), "--tpm2", "--ctrl", fmt.Sprintf("type=tcp,port=%d", data+1),
		"--server", fmt.Sprintf("type=tcp,port=%d", data), "--flags", "not-need-init,startup-clear")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	time.Sleep(1500 * time.Millisecond)

	bus := exec.Command("dbus-daemon", "--session", "--nofork", "--print-address")
	output, err := bus.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := bus.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bus.Process.Kill(); _ = bus.Wait() })
	address, err := bufio.NewReader(output).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	address = strings.TrimSpace(address)

	broker := exec.Command("tpm2-abrmd", "--session", "--allow-root", fmt.Sprintf("--tcti=swtpm:host=127.0.0.1,port=%d", data))
	broker.Env = append(os.Environ(), "DBUS_SESSION_BUS_ADDRESS="+address)
	if err := broker.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Process.Kill(); _ = broker.Wait() })
	time.Sleep(1500 * time.Millisecond)
	return []string{"DBUS_SESSION_BUS_ADDRESS=" + address, "TPM2TOOLS_TCTI=tabrmd:bus_type=session"}
}

func TestSwtpmAttestationRoundTrip(t *testing.T) {
	prover := &TPMProver{Environment: startSwtpm(t, 2321)}
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
	quote, err := prover.Quote(nonce, repeat("ab"), repeat("cd"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (TPMVerifier{}).CheckQuote(hello, quote, qualifying); err != nil {
		t.Fatalf("a genuine quote must pass: %v", err)
	}
	forged := roundTrip(quote)
	forged["pcrs"].(Obj)["7"] = repeat("11")
	if _, err := (TPMVerifier{}).CheckQuote(hello, forged, qualifying); err == nil {
		t.Fatal("a forged PCR must be detected")
	}
	if _, err := (TPMVerifier{}).CheckQuote(hello, quote, "00"+qualifying[2:]); err == nil {
		t.Fatal("a wrong nonce must be detected")
	}
	other, _ := prover.Quote(nonce, repeat("ab"), repeat("ce"))
	if _, err := (TPMVerifier{}).CheckQuote(hello, other, qualifying); err == nil {
		t.Fatal("a quote for other keys must be detected")
	}
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	swapped := Obj{"ek_pub": hello["ek_pub"], "ak_name": hello["ak_name"], "ak_pub": base64.StdEncoding.EncodeToString(softwareKey(stranger, attestationKeyRequired))}
	if _, err := Attest(swappingProver{prover, swapped}, TPMVerifier{}, ek, NewNonce(), repeat("ab"), repeat("cd")); err == nil {
		t.Fatal("an attestation key outside the TPM must be detected")
	}
}

type swappingProver struct {
	Prover
	hello Obj
}

func (swapping swappingProver) Hello() (Obj, error) { return swapping.hello, nil }

func TestClusterFormsWithRealAttestation(t *testing.T) {
	var environments [][]string
	for _, port := range []int{2341, 2351, 2361} {
		environments = append(environments, startSwtpm(t, port))
	}
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
		return &TPMProver{Environment: environments[index]}
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

func TestSwtpmAnswersConcurrentAttestations(t *testing.T) {
	prover := &TPMProver{Environment: startSwtpm(t, 2371)}
	hello, err := prover.Hello()
	if err != nil {
		t.Fatal(err)
	}
	ek, _ := EKHash(hello)
	errors := make(chan error, 6)
	for index := 0; index < 6; index++ {
		go func() {
			_, err := Attest(prover, TPMVerifier{}, ek, NewNonce(), repeat("ab"), repeat("cd"))
			errors <- err
		}()
	}
	for index := 0; index < 6; index++ {
		if err := <-errors; err != nil {
			t.Errorf("concurrent attestation %d: %v", index, err)
		}
	}
}
