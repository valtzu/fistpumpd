package cluster

import (
	"errors"
	"fmt"
)

type Candidate struct{ cfg Config }

func NewCandidate(cfg Config) *Candidate { return &Candidate{cfg: cfg} }

func (candidate *Candidate) Handle(method string, payload Obj) (Obj, error) {
	if len(method) > 7 && method[:7] == "attest_" {
		reply, _, err := ServeAttestation(candidate.cfg.TPM, candidate.cfg.Record, false, method, payload)
		return reply, err
	}
	if method == "commit" {
		return Obj{"length": 0}, nil
	}
	return nil, refuse("unknown method %s", method)
}

func (candidate *Candidate) Join(seeds []string) (*Node, error) {
	var refusal error
	for _, address := range seeds {
		if _, err := candidate.cfg.Transport.Call(address, "join", Obj{"node": candidate.cfg.Record, "facts": candidate.cfg.Facts}); err != nil {
			var refused *Refused
			if errors.As(err, &refused) {
				refusal = err
			}
			continue
		}
		reply, err := candidate.cfg.Transport.Call(address, "log", Obj{"from": 0})
		if err != nil {
			continue
		}
		entries, _ := reply["entries"].([]any)
		lines := make([]string, 0, len(entries))
		for _, entry := range entries {
			lines = append(lines, string(Marshal(entry)))
		}
		log, err := ChainFromLines(lines, candidate.cfg.BuildCertificate)
		if err != nil {
			return nil, err
		}
		if log.SlotOf(str(candidate.cfg.Record, "sign_pub")) < 0 {
			return nil, refuse("the log does not contain this node")
		}
		if err := candidate.verifyMembers(log); err != nil {
			return nil, err
		}
		for _, line := range lines {
			if err := candidate.cfg.Store.Append(line); err != nil {
				return nil, err
			}
		}
		return newNode(candidate.cfg, log), nil
	}
	if refusal != nil {
		return nil, refusal
	}
	return nil, &TransportError{Message: "no seed answered"}
}

func (candidate *Candidate) checkPolicy(pcrs map[string]string) error {
	if candidate.cfg.Policy == nil {
		return fmt.Errorf("no policy")
	}
	_, err := candidate.cfg.Policy.Check(pcrs)
	if err != nil && candidate.cfg.PolicyRefresh != nil {
		_, err = candidate.cfg.PolicyRefresh().Check(pcrs)
	}
	return err
}

func (candidate *Candidate) verifyMembers(log *Chain) error {
	var others []*Member
	for _, member := range log.Active() {
		if member.SignPub() != str(candidate.cfg.Record, "sign_pub") {
			others = append(others, member)
		}
	}
	if len(others) == 0 || candidate.cfg.Verifier == nil {
		return refuse("the log has no member that this node can attest")
	}
	needed, passed, failure := Quorum(len(others)), 0, ""
	for _, member := range others {
		fingerprint := str(member.Node, "tls_fp")
		prover := candidate.cfg.Transport.Prover(member.Addr(), fingerprint)
		pcrs, err := Attest(prover, candidate.cfg.Verifier, str(member.Node, "ek_hash"), NewNonce(), member.SignPub(), fingerprint)
		if err == nil {
			err = candidate.checkPolicy(pcrs)
		}
		if err != nil {
			failure = fmt.Sprintf("slot %d: %v", member.Slot, err)
			continue
		}
		if passed++; passed >= needed {
			return nil
		}
	}
	return refuse("%d of the %d members needed passed attestation by this node (%s)", passed, needed, failure)
}
