package cluster

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func freePort(t testing.TB) int {
	t.Helper()
	for attempt := 0; attempt < 200; attempt++ {
		port := 20000 + rand.Intn(10000)
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			listener.Close()
			return port
		}
	}
	t.Fatal("no free port below the ephemeral range")
	return 0
}

type live struct {
	node    *testNode
	server  *Server
	key     string
	cert    string
	fp      string
	switchH *Switch
}

func newLive(t *testing.T, pins func(string) string, name string) *live {
	t.Helper()
	l := &live{switchH: &Switch{}}
	var err error
	l.key, l.cert, l.fp, err = CreateTLS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	l.node = newTestNode(t, nil, name)
	l.node.record["tls_fp"] = l.fp
	l.node.record["addr"] = fmt.Sprintf("127.0.0.1:%d", freePort(t))
	l.node.cfg.Record = l.node.record
	l.node.cfg.Transport = &HTTPSTransport{Pins: pins}
	l.server, err = StartServer(l.switchH, str(l.node.record, "addr"), l.cert, l.key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.server.Stop)
	return l
}

func TestThreeNodesOverRealTLS(t *testing.T) {
	pins := map[string]string{}
	lookup := func(address string) string { return pins[address] }
	items := []*live{newLive(t, lookup, "a"), newLive(t, lookup, "b"), newLive(t, lookup, "c")}
	founder, err := Found(items[0].node.cfg)
	if err != nil {
		t.Fatal(err)
	}
	items[0].switchH.Set(founder)
	pins[str(items[0].node.record, "addr")] = items[0].fp
	for _, item := range items[1:] {
		candidate := NewCandidate(item.node.cfg)
		item.switchH.Set(candidate)
		member, err := candidate.Join([]string{str(items[0].node.record, "addr")})
		if err != nil {
			t.Fatal(err)
		}
		item.switchH.Set(member)
		pins[str(item.node.record, "addr")] = item.fp
	}
	if founder.Log.Len() != 3 {
		t.Fatalf("length %d", founder.Log.Len())
	}
}

func TestAWrongCertificateIsRejected(t *testing.T) {
	item := newLive(t, nil, "a")
	item.switchH.Set(handlerFunc(func(method string, payload Obj) (Obj, error) { return Obj{"ok": true}, nil }))
	transport := &HTTPSTransport{}
	if reply, err := transport.Call(str(item.node.record, "addr"), "x", Obj{}); err != nil || reply["ok"] != true {
		t.Fatalf("%v", err)
	}
	_, err := transport.call(str(item.node.record, "addr"), "x", Obj{}, repeat("0"))
	if err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("%v", err)
	}
}

type handlerFunc func(method string, payload Obj) (Obj, error)

func (f handlerFunc) Handle(method string, payload Obj) (Obj, error) { return f(method, payload) }

func TestARefusalTravelsWithItsReason(t *testing.T) {
	item := newLive(t, nil, "r")
	item.switchH.Set(handlerFunc(func(string, Obj) (Obj, error) {
		return nil, &Refused{Reason: "no", Pending: Obj{"index": 3}}
	}))
	_, err := (&HTTPSTransport{}).Call(str(item.node.record, "addr"), "x", Obj{})
	var refused *Refused
	if !errors.As(err, &refused) || refused.Reason != "no" || integer(refused.Pending, "index") != 3 {
		t.Fatalf("%v", err)
	}
}

func TestControlSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	server, err := StartControl(handlerFunc(func(method string, payload Obj) (Obj, error) {
		if method == "boom" {
			return nil, &Refused{Reason: "refused"}
		}
		return Obj{"method": method}, nil
	}), path)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Stop()
	reply, err := ControlCall(path, "status", Obj{})
	if err != nil || reply["method"] != "status" {
		t.Fatalf("%v", err)
	}
	if _, err := ControlCall(path, "boom", Obj{}); err == nil {
		t.Fatal("refusal expected")
	}
}

func TestProbeFindsResponders(t *testing.T) {
	responder, err := StartResponder(0, "127.0.0.1", func() Obj { return Obj{"addr": "10.0.0.5:17947", "role": "member"} })
	if err != nil {
		t.Fatal(err)
	}
	defer responder.Stop()
	found := Probe([]Target{{"127.0.0.1", responder.Port()}}, 1500*time.Millisecond, "127.0.0.1")
	if len(found) != 1 || found[0]["addr"] != "10.0.0.5:17947" {
		t.Fatalf("%v", found)
	}
}
