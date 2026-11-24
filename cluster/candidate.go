package cluster

import "errors"

type Candidate struct{ cfg Config }

func NewCandidate(cfg Config) *Candidate { return &Candidate{cfg: cfg} }

func (candidate *Candidate) Handle(method string, payload Obj) (Obj, error) {
	if len(method) > 7 && method[:7] == "attest_" {
		reply, _, err := ServeAttestation(candidate.cfg.TPM, method, payload)
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
