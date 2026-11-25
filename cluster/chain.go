package cluster

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
)

var (
	hexDigest   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	addressHost = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.:-]{0,251}[A-Za-z0-9])?$`)
)

const Zero = "0000000000000000000000000000000000000000000000000000000000000000"

type ChainError struct{ Message string }

func (e *ChainError) Error() string { return e.Message }

func chainError(format string, args ...any) error {
	return &ChainError{Message: fmt.Sprintf(format, args...)}
}

func Quorum(members int) int {
	if members < 1 {
		panic("a quorum needs members")
	}
	faulty := (members - 1) / 3
	return (members + faulty + 2) / 2
}

func EntryHash(entry Obj) string {
	core := Obj{"index": entry["index"], "prev": entry["prev"], "type": entry["type"], "body": entry["body"]}
	data, err := Canonical(core)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hashBytes(entry Obj) []byte {
	raw, _ := hex.DecodeString(EntryHash(entry))
	return raw
}

func SignEntry(key ed25519.PrivateKey, entry Obj) string {
	return hex.EncodeToString(ed25519.Sign(key, hashBytes(entry)))
}

func VerifyMember(publicHex string, entry Obj, signatureHex string) bool {
	public, err := hex.DecodeString(publicHex)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return false
	}
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false
	}
	return ed25519.Verify(public, hashBytes(entry), signature)
}

func VerifyMessage(publicHex string, message []byte, signatureHex string) bool {
	public, err := hex.DecodeString(publicHex)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return false
	}
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false
	}
	return ed25519.Verify(public, message, signature)
}

func parseCertificate(certificatePEM []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(certificatePEM)
	if block == nil {
		return nil, fmt.Errorf("no certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return certificate.PublicKey, nil
}

func VerifyBuild(certificatePEM []byte, entry Obj) bool {
	signature, ok := entry["build_sig"].(string)
	if len(certificatePEM) == 0 || !ok {
		return false
	}
	public, err := parseCertificate(certificatePEM)
	if err != nil {
		return false
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(signature)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(hashBytes(entry))
	switch key := public.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], raw) == nil
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(key, digest[:], raw)
	}
	return false
}

func SignBuild(key crypto.Signer, entry Obj) (string, error) {
	digest := sha256.Sum256(hashBytes(entry))
	signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

type Member struct {
	Slot   int
	Number int
	Node   Obj
	Roles  []string
	Facts  Obj
	Policy Obj
	PCR1   string
	Status string
}

func (member *Member) Addr() string    { return str(member.Node, "addr") }
func (member *Member) SignPub() string { return str(member.Node, "sign_pub") }

type Chain struct {
	BuildCertificate []byte
	Entries          []Obj
	Members          map[int]*Member
	Topology         Obj
}

func NewChain(buildCertificate []byte) *Chain {
	return &Chain{BuildCertificate: buildCertificate, Members: map[int]*Member{}}
}

func (chain *Chain) Len() int { return len(chain.Entries) }

func (chain *Chain) Head() string {
	if len(chain.Entries) == 0 {
		return Zero
	}
	return EntryHash(chain.Entries[len(chain.Entries)-1])
}

func (chain *Chain) Active() []*Member {
	slots := make([]int, 0, len(chain.Members))
	for slot, member := range chain.Members {
		if member.Status == "active" {
			slots = append(slots, slot)
		}
	}
	sort.Ints(slots)
	active := make([]*Member, len(slots))
	for index, slot := range slots {
		active[index] = chain.Members[slot]
	}
	return active
}

func (chain *Chain) Member(slot int) *Member {
	member := chain.Members[slot]
	if member != nil && member.Status == "active" {
		return member
	}
	return nil
}

func (chain *Chain) SlotOf(signPub string) int {
	for _, member := range chain.Active() {
		if member.SignPub() == signPub {
			return member.Slot
		}
	}
	return -1
}

func (chain *Chain) RankOf(slot int) int {
	for rank, member := range chain.Active() {
		if member.Slot == slot {
			return rank
		}
	}
	return -1
}

func (chain *Chain) TopologyVersion() int {
	if chain.Topology == nil {
		return 0
	}
	return integer(chain.Topology, "version")
}

func (chain *Chain) Check(entry Obj) error {
	kind, _ := entry["type"].(string)
	if kind != "admit" && kind != "evict" && kind != "topology" && kind != "reset" {
		return chainError("unknown entry type")
	}
	index, ok := asInt(entry["index"])
	if !ok || index != len(chain.Entries) {
		return chainError("index %v is not the next one (%d)", entry["index"], len(chain.Entries))
	}
	if prev, _ := entry["prev"].(string); prev != chain.Head() {
		return chainError("prev does not match the head")
	}
	if _, ok := entry["body"].(Obj); !ok {
		return chainError("body is an object")
	}
	if _, err := Canonical(core(entry)); err != nil {
		return chainError("%s", err.Error())
	}
	switch kind {
	case "admit":
		return chain.checkAdmit(entry)
	case "evict":
		return chain.checkEvict(entry)
	case "topology":
		return chain.checkTopology(entry)
	}
	return chain.checkReset(entry)
}

func (chain *Chain) Append(entry Obj) error {
	if err := chain.Check(entry); err != nil {
		return err
	}
	switch entry["type"] {
	case "admit":
		chain.applyAdmit(entry)
	case "evict":
		chain.Members[integer(entry["body"].(Obj), "slot")].Status = "evicted"
	case "topology":
		body := entry["body"].(Obj)
		chain.Topology = Obj{"version": integer(body, "version"), "digest": str(body, "digest")}
	case "reset":
		keep := map[int]bool{}
		for _, slot := range entry["body"].(Obj)["members"].([]any) {
			number, _ := asInt(slot)
			keep[number] = true
		}
		for slot, member := range chain.Members {
			if keep[slot] {
				member.Status = "active"
			} else {
				member.Status = "evicted"
			}
		}
	}
	chain.Entries = append(chain.Entries, entry)
	return nil
}

func (chain *Chain) signers(entry Obj, excluded ...int) map[int]bool {
	valid := map[int]bool{}
	signatures, _ := entry["sigs"].(Obj)
	for key, value := range signatures {
		slot, err := strconv.Atoi(key)
		if err != nil {
			continue
		}
		member := chain.Member(slot)
		signature, _ := value.(string)
		if member == nil || contains2(excluded, slot) || !VerifyMember(member.SignPub(), entry, signature) {
			continue
		}
		valid[slot] = true
	}
	return valid
}

func contains2(list []int, wanted int) bool {
	for _, item := range list {
		if item == wanted {
			return true
		}
	}
	return false
}

func (chain *Chain) requireQuorum(entry Obj, excluded ...int) error {
	needed := Quorum(len(chain.Active()))
	got := len(chain.signers(entry, excluded...))
	if got < needed {
		return chainError("%d valid signatures, %d needed", got, needed)
	}
	return nil
}

func validAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || !addressHost.MatchString(host) {
		return false
	}
	number, err := strconv.Atoi(port)
	return err == nil && number > 0 && number < 65536
}

func NodeRecord(value any) (Obj, error) {
	node, ok := value.(Obj)
	if !ok {
		return nil, chainError("a node record has sign_pub, tls_fp and ek_hash")
	}
	for _, key := range []string{"sign_pub", "tls_fp", "ek_hash"} {
		if text, ok := node[key].(string); !ok || !hexDigest.MatchString(text) {
			return nil, chainError("a node record has sign_pub, tls_fp and ek_hash, each 64 lower-case hex digits")
		}
	}
	if address, ok := node["addr"].(string); !ok || !validAddress(address) {
		return nil, chainError("a node record has an address, host:port")
	}
	return node, nil
}

func (chain *Chain) checkAdmit(entry Obj) error {
	body := entry["body"].(Obj)
	node, err := NodeRecord(body["node"])
	if err != nil {
		return err
	}
	roles, ok := body["roles"].([]any)
	if !ok {
		return chainError("roles is a list")
	}
	for _, role := range roles {
		if name, isString := role.(string); !isString || !roleName.MatchString(name) {
			return chainError("roles are lower-case words")
		}
	}
	if facts, present := body["facts"]; present {
		if _, isObject := facts.(Obj); !isObject {
			return chainError("facts is an object")
		}
	}
	for _, member := range chain.Active() {
		if member.SignPub() == str(node, "sign_pub") || str(member.Node, "ek_hash") == str(node, "ek_hash") {
			return chainError("node is already a member")
		}
	}
	founder, _ := body["founder"].(bool)
	if len(chain.Entries) == 0 {
		if !founder {
			return chainError("the first entry admits a founder")
		}
		signatures, _ := entry["sigs"].(Obj)
		signature, _ := signatures["0"].(string)
		if !VerifyMember(str(node, "sign_pub"), entry, signature) {
			return chainError("founder signature is invalid")
		}
		return nil
	}
	if founder {
		return chainError("only the first entry is a founder")
	}
	if len(chain.Active()) == 0 {
		return chainError("no members, a reset is needed")
	}
	return chain.requireQuorum(entry)
}

func (chain *Chain) applyAdmit(entry Obj) {
	body := entry["body"].(Obj)
	facts, _ := body["facts"].(Obj)
	policy, _ := body["policy"].(Obj)
	if facts == nil {
		facts = Obj{}
	}
	if policy == nil {
		policy = Obj{}
	}
	slot := integer(entry, "index")
	chain.Members[slot] = &Member{
		Slot: slot, Number: len(chain.Members), Node: body["node"].(Obj), Roles: stringList(body["roles"]), Facts: facts, Policy: policy,
		PCR1: str(body, "pcr1"), Status: "active",
	}
	if topology, ok := body["topology"].(Obj); ok && len(topology) > 0 {
		chain.Topology = topology
	}
}

func (chain *Chain) checkEvict(entry Obj) error {
	slot, ok := asInt(entry["body"].(Obj)["slot"])
	if !ok || chain.Member(slot) == nil {
		return chainError("evict names an active member")
	}
	if len(chain.Active()) < 2 {
		return chainError("the last member is removed by a reset")
	}
	return chain.requireQuorum(entry, slot)
}

func (chain *Chain) checkTopology(entry Obj) error {
	body := entry["body"].(Obj)
	version, ok := asInt(body["version"])
	_, isString := body["digest"].(string)
	current := chain.TopologyVersion()
	if !ok || version <= current || !isString {
		return chainError("topology version must be above %d", current)
	}
	return chain.requireQuorum(entry)
}

func (chain *Chain) checkReset(entry Obj) error {
	slots, ok := entry["body"].(Obj)["members"].([]any)
	if !ok || len(slots) == 0 {
		return chainError("reset names known members")
	}
	for _, item := range slots {
		slot, isInt := asInt(item)
		if _, known := chain.Members[slot]; !isInt || !known {
			return chainError("reset names known members")
		}
	}
	if !VerifyBuild(chain.BuildCertificate, entry) {
		return chainError("reset is not signed by the build key")
	}
	return nil
}

func (chain *Chain) Lines() []string {
	lines := make([]string, len(chain.Entries))
	for index, entry := range chain.Entries {
		lines[index] = string(Marshal(entry))
	}
	return lines
}

func ChainFromLines(lines []string, buildCertificate []byte) (*Chain, error) {
	chain := NewChain(buildCertificate)
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		entry, err := DecodeObj([]byte(line))
		if err != nil {
			return nil, err
		}
		if err := chain.Append(entry); err != nil {
			return nil, err
		}
	}
	return chain, nil
}
