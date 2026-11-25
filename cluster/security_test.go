package cluster

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sizedField(data []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(data))), data...)
}

func softwareKey(key *ecdsa.PrivateKey, attributes uint32) []byte {
	var area []byte
	area = binary.BigEndian.AppendUint16(area, tpmAlgECC)
	area = binary.BigEndian.AppendUint16(area, tpmAlgSHA256)
	area = binary.BigEndian.AppendUint32(area, attributes)
	area = append(area, sizedField(nil)...)
	for _, value := range []uint16{tpmAlgNull, tpmAlgECDSA, tpmAlgSHA256, tpmCurveP256, tpmAlgNull} {
		area = binary.BigEndian.AppendUint16(area, value)
	}
	area = append(area, sizedField(key.X.FillBytes(make([]byte, 32)))...)
	area = append(area, sizedField(key.Y.FillBytes(make([]byte, 32)))...)
	return sizedField(area)
}

func softwareQuote(t *testing.T, key *ecdsa.PrivateKey, magic uint32, qualifying, bitmap, pcrValues []byte) (string, string) {
	t.Helper()
	var message []byte
	message = binary.BigEndian.AppendUint32(message, magic)
	message = binary.BigEndian.AppendUint16(message, tpmAttestQuote)
	message = append(message, sizedField(make([]byte, 34))...)
	message = append(message, sizedField(qualifying)...)
	message = append(message, make([]byte, tpmClockInfo+tpmFirmwareSize)...)
	message = binary.BigEndian.AppendUint32(message, 1)
	message = binary.BigEndian.AppendUint16(message, tpmAlgSHA256)
	message = append(message, byte(len(bitmap)))
	message = append(message, bitmap...)
	digest := sha256.Sum256(pcrValues)
	message = append(message, sizedField(digest[:])...)
	sum := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	var signature []byte
	signature = binary.BigEndian.AppendUint16(signature, tpmAlgECDSA)
	signature = binary.BigEndian.AppendUint16(signature, tpmAlgSHA256)
	signature = append(signature, sizedField(r.Bytes())...)
	signature = append(signature, sizedField(s.Bytes())...)
	return base64.StdEncoding.EncodeToString(message), base64.StdEncoding.EncodeToString(signature)
}

func TestQuoteVerification(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	qualifying := sha256.Sum256([]byte("nonce and keys"))
	pcrs := Obj{}
	var values []byte
	for index, number := range []string{"0", "1", "2", "3", "7", "11"} {
		value := sha256.Sum256([]byte{byte(index)})
		pcrs[number] = hex.EncodeToString(value[:])
		values = append(values, value[:]...)
	}
	selection := []byte{0x8f, 0x08, 0x00}
	hello := func(attributes uint32) Obj {
		return Obj{"ak_pub": base64.StdEncoding.EncodeToString(softwareKey(key, attributes))}
	}
	check := func(attributes, magic uint32, bitmap []byte, mutate func(Obj)) error {
		message, signature := softwareQuote(t, key, magic, qualifying[:], bitmap, values)
		quote := Obj{"pcrs": roundTrip(pcrs), "message": message, "signature": signature}
		if mutate != nil {
			mutate(quote)
		}
		_, err := (TPMVerifier{}).CheckQuote(hello(attributes), quote, hex.EncodeToString(qualifying[:]))
		return err
	}
	if err := check(attestationKeyRequired, tpmGenerated, selection, nil); err != nil {
		t.Fatalf("a well-formed quote must pass: %v", err)
	}
	cases := map[string]error{
		"key that is not restricted":     check(attestationKeyRequired&^attributeRestricted, tpmGenerated, selection, nil),
		"key made outside the TPM":       check(attestationKeyRequired&^attributeSensitiveDataOrigin, tpmGenerated, selection, nil),
		"key that also decrypts":         check(attestationKeyRequired|attributeDecrypt, tpmGenerated, selection, nil),
		"structure the TPM did not make": check(attestationKeyRequired, 0, selection, nil),
		"another PCR selection":          check(attestationKeyRequired, tpmGenerated, []byte{0x0f, 0x08, 0x01}, nil),
		"other PCR values": check(attestationKeyRequired, tpmGenerated, selection, func(quote Obj) {
			quote["pcrs"].(Obj)["7"] = repeat("1")
		}),
		"trailing bytes": check(attestationKeyRequired, tpmGenerated, selection, func(quote Obj) {
			raw, _ := base64.StdEncoding.DecodeString(quote["message"].(string))
			quote["message"] = base64.StdEncoding.EncodeToString(append(raw, 0))
		}),
	}
	for name, err := range cases {
		if err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
	if _, err := (TPMVerifier{}).CheckQuote(Obj{"ak_pub": "AAA="}, Obj{}, hex.EncodeToString(qualifying[:])); err == nil {
		t.Error("a truncated key must be refused")
	}
}

func TestAMalformedCommitDoesNotBlockTheNode(t *testing.T) {
	network := NewNetwork()
	nodes := makeCluster(t, network, 2)
	_, head, length, _ := nodes[0].Snapshot()
	for _, body := range []Obj{
		{"version": 2, "digest": "x", "fraction": 1.5},
		{"version": 2, "digest": "x", "text": "\xff"},
	} {
		entry := Obj{"index": length, "prev": head, "type": "topology", "body": body, "sigs": Obj{"0": "00", "1": "00"}}
		if _, err := nodes[0].Handle("commit", Obj{"entry": entry}); err == nil {
			t.Fatal("an entry that has no canonical form must be refused")
		}
	}
	for _, payload := range []Obj{
		{"entry": Obj{"index": length, "prev": head, "type": "evict", "body": "none"}},
		{"entry": Obj{"index": length, "prev": head, "type": "topology", "body": Obj{"version": 1.5}}},
	} {
		if _, err := nodes[0].Handle("propose", payload); err == nil {
			t.Fatal("a malformed proposal must be refused")
		}
	}
	answered := make(chan struct{})
	go func() {
		_, _ = nodes[0].Handle("hello", Obj{})
		close(answered)
	}()
	select {
	case <-answered:
	case <-time.After(5 * time.Second):
		t.Fatal("the node no longer answers")
	}
}

type relay struct {
	network *Network
	victim  string
}

func (r relay) Handle(method string, payload Obj) (Obj, error) {
	if strings.HasPrefix(method, "attest_") {
		return view{r.network}.Call(r.victim, method, payload)
	}
	return Obj{}, nil
}

func TestAQuoteRelayedFromAnotherNodeIsRefused(t *testing.T) {
	network := NewNetwork()
	founder := makeFounder(t, network, "n0")
	victim := newTestNode(t, network, "victim")
	network.Register(str(victim.record, "addr"), NewCandidate(victim.cfg))
	attacker := newTestNode(t, network, "attacker", func(n *testNode) { n.record["ek_hash"] = victim.record["ek_hash"] })
	network.Register(str(attacker.record, "addr"), relay{network, str(victim.record, "addr")})
	_, err := NewCandidate(attacker.cfg).Join([]string{str(founder.Record(), "addr")})
	refusedWith(t, err, "signature")
	if founder.Log.Len() != 1 {
		t.Fatal("the log must not grow")
	}
}

func TestAQuoteIsOnlyGivenForAFreshNonce(t *testing.T) {
	node := newTestNode(t, NewNetwork(), "n0")
	candidate := NewCandidate(node.cfg)
	for _, payload := range []Obj{{"qualifying": repeat("a")}, {"nonce": repeat("a")}, {"nonce": "zz"}} {
		if _, err := candidate.Handle("attest_quote", payload); err == nil {
			t.Fatalf("%v must be refused", payload)
		}
	}
	if _, err := candidate.Handle("attest_quote", Obj{"nonce": NewNonce()}); err != nil {
		t.Fatal(err)
	}
}

func TestACandidateRefusesAClusterThatFailsItsPolicy(t *testing.T) {
	network := NewNetwork()
	badPCRs := map[string]string{}
	for key, value := range goodPCRs {
		badPCRs[key] = value
	}
	badPCRs["11"] = repeat("9")
	rogue := makeFounder(t, network, "rogue", func(n *testNode) {
		n.tpm = NewFakeTPM(badPCRs)
		n.cfg.TPM = n.tpm
		hello, _ := n.tpm.Hello()
		n.record["ek_hash"], _ = EKHash(hello)
		document := policyDocument()
		document["versions"] = []any{Obj{"version": "evil", "pcr11": badPCRs["11"]}, Obj{"version": "30", "pcr11": goodPCRs["11"]}}
		n.cfg.Policy = NewPolicy(document)
	})
	joiner := newTestNode(t, network, "joiner")
	_, err := admit(t, network, joiner, rogue)
	refusedWith(t, err, "passed attestation by this node")
	if lines, _ := joiner.cfg.Store.LoadLines(); len(lines) != 0 {
		t.Fatal("a refused log must not be stored")
	}
}

func TestEntriesWithUnsafeNamesAreRefused(t *testing.T) {
	node := newTestNode(t, NewNetwork(), "n0")
	found := func(change func(body Obj)) error {
		body := Obj{"node": roundTrip(node.record), "roles": []any{"server"}, "facts": Obj{}, "founder": true, "policy": Obj{}}
		change(body)
		entry := Obj{"index": 0, "prev": Zero, "type": "admit", "body": body}
		entry["sigs"] = Obj{"0": SignEntry(node.key, entry)}
		return NewChain(nil).Append(entry)
	}
	if err := found(func(Obj) {}); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(Obj){
		"a role that is a path":        func(body Obj) { body["roles"] = []any{"../../etc/cron.d/x"} },
		"an address with a line break": func(body Obj) { body["node"].(Obj)["addr"] = "10.0.0.1\nserver: evil:1" },
		"an address without a port":    func(body Obj) { body["node"].(Obj)["addr"] = "10.0.0.1" },
		"a key that is not a digest":   func(body Obj) { body["node"].(Obj)["tls_fp"] = "abcd" },
		"facts that are not an object": func(body Obj) { body["facts"] = "big" },
	}
	for name, change := range cases {
		if found(change) == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}

func TestTheCachedPolicyIsVerifiedAgain(t *testing.T) {
	open, keyring := signedPolicyBucket(t)
	cache := t.TempDir()
	if _, err := RefreshPolicy([]string{"https://x/c"}, keyring, cache, open); err != nil {
		t.Fatal(err)
	}
	versions := filepath.Join(cacheDirectory(cache, "https://x/c"), "versions.json")
	if err := os.WriteFile(versions, []byte(`{"versions":[{"version":"evil","pcr11":"`+repeat("9")+`"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	down := func(string) ([]byte, error) { return nil, os.ErrDeadlineExceeded }
	if _, err := RefreshPolicy([]string{"https://x/c"}, keyring, cache, down); err == nil {
		t.Fatal("a cache that was changed on disk must be refused")
	}
}

func TestPlainCredentialsAreNotWorldReadable(t *testing.T) {
	directory := t.TempDir()
	tokens, err := NewTokens(filepath.Join(directory, "tokens"), filepath.Join(directory, "credstore"), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := tokens.Create(); err != nil {
		t.Fatal(err)
	}
	if err := tokens.InstallCredentials([]string{"server"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(directory, "credstore", "k3s.token"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", info, err)
	}
}

func TestOnlyAnActiveMemberQuotesForAnEarlierRelease(t *testing.T) {
	network := NewNetwork()
	nodes := makeCluster(t, network, 3)
	legacy := Obj{"qualifying": repeat("a")}
	if _, err := nodes[1].Handle("attest_quote", roundTrip(legacy)); err != nil {
		t.Fatalf("an active member answers a verifier of the earlier release: %v", err)
	}
	network.SetDown(str(nodes[1].Record(), "addr"), true)
	nodes[0].SetObserver(unhealthy{})
	nodes[2].SetObserver(unhealthy{})
	if _, err := nodes[0].ProposeEvict(nodes[1].Slot(), "test"); err != nil {
		t.Fatal(err)
	}
	network.SetDown(str(nodes[1].Record(), "addr"), false)
	nodes[1].CatchUp()
	if nodes[1].Slot() >= 0 {
		t.Fatal("the node must see its eviction")
	}
	if _, err := nodes[1].Handle("attest_quote", roundTrip(legacy)); err == nil {
		t.Fatal("an evicted node must not quote over qualifying data a caller chose")
	}
}

type unhealthy struct{}

func (unhealthy) Healthy(*Member) bool { return false }
