package cluster

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	maxBody    = 8 << 20
	callTimout = 30 * time.Second
)

type Handler interface {
	Handle(method string, payload Obj) (Obj, error)
}

type Switch struct {
	mutex  sync.RWMutex
	target Handler
}

func (s *Switch) Set(target Handler) {
	s.mutex.Lock()
	s.target = target
	s.mutex.Unlock()
}

func (s *Switch) Handle(method string, payload Obj) (Obj, error) {
	s.mutex.RLock()
	target := s.target
	s.mutex.RUnlock()
	if target == nil {
		return nil, &TransportError{Message: "not ready"}
	}
	return target.Handle(method, payload)
}

func rpcHandler(target Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/rpc/", func(w http.ResponseWriter, r *http.Request) {
		reply := func(status int, document any) {
			body, _ := json.Marshal(document)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write(body)
		}
		if r.Method != http.MethodPost {
			reply(405, Obj{"error": "POST only"})
			return
		}
		data, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil || len(data) > maxBody {
			reply(413, Obj{"error": "too large"})
			return
		}
		payload := Obj{}
		if len(bytes.TrimSpace(data)) > 0 {
			if payload, err = DecodeObj(data); err != nil {
				reply(400, Obj{"error": "bad request: " + err.Error()})
				return
			}
		}
		result, err := target.Handle(r.URL.Path[len("/rpc/"):], payload)
		var refused *Refused
		var attestation *AttestationError
		var transport *TransportError
		switch {
		case err == nil:
			if result == nil {
				result = Obj{}
			}
			reply(200, result)
		case errors.As(err, &refused):
			reply(409, Obj{"error": refused.Reason, "pending": refused.Pending})
		case errors.As(err, &attestation):
			reply(409, Obj{"error": attestation.Message, "pending": nil})
		case errors.As(err, &transport):
			reply(502, Obj{"error": transport.Message})
		default:
			reply(500, Obj{"error": err.Error()})
		}
	})
	return mux
}

type Server struct {
	server   *http.Server
	listener net.Listener
}

func StartServer(target Handler, bind, certFile, keyFile string) (*Server, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	listener, err := tls.Listen("tcp", bind, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13})
	if err != nil {
		return nil, err
	}
	server := &http.Server{Handler: rpcHandler(target), ReadHeaderTimeout: 10 * time.Second, ErrorLog: nil}
	go func() { _ = server.Serve(listener) }()
	return &Server{server: server, listener: listener}, nil
}

func (s *Server) Port() int { return s.listener.Addr().(*net.TCPAddr).Port }

func (s *Server) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.server.Shutdown(ctx)
	_ = s.server.Close()
}

type HTTPSTransport struct {
	Pins func(address string) string
}

func (transport *HTTPSTransport) Call(address, method string, payload Obj) (Obj, error) {
	pin := ""
	if transport.Pins != nil {
		pin = transport.Pins(address)
	}
	return transport.call(address, method, payload, pin)
}

func (transport *HTTPSTransport) call(address, method string, payload Obj, pin string) (Obj, error) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS13, InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if pin != "" && (len(raw) == 0 || Fingerprint(raw[0]) != pin) {
				return fmt.Errorf("certificate is not the pinned one")
			}
			return nil
		},
	}
	client := &http.Client{Timeout: callTimout, Transport: &http.Transport{TLSClientConfig: config, DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	response, err := client.Post("https://"+address+"/rpc/"+method, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, &TransportError{Message: fmt.Sprintf("%s: %v", address, err)}
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBody))
	if err != nil {
		return nil, &TransportError{Message: fmt.Sprintf("%s: %v", address, err)}
	}
	document, err := DecodeObj(data)
	if err != nil {
		return nil, &TransportError{Message: fmt.Sprintf("%s: bad reply", address)}
	}
	switch response.StatusCode {
	case 200:
		return document, nil
	case 409:
		pending, _ := document["pending"].(Obj)
		return nil, &Refused{Reason: str(document, "error"), Pending: pending}
	}
	return nil, &TransportError{Message: fmt.Sprintf("%s: HTTP %d: %s", address, response.StatusCode, str(document, "error"))}
}

func (transport *HTTPSTransport) Prover(address, fingerprint string) Prover {
	return RemoteProver{Call: func(method string, payload Obj) (Obj, error) {
		return transport.call(address, method, payload, fingerprint)
	}}
}

type ControlServer struct {
	server *http.Server
	path   string
}

func StartControl(target Handler, path string) (*ControlServer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		return nil, err
	}
	server := &http.Server{Handler: rpcHandler(target), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = server.Serve(listener) }()
	return &ControlServer{server: server, path: path}, nil
}

func (c *ControlServer) Stop() {
	_ = c.server.Close()
	_ = os.Remove(c.path)
}

func ControlCall(path, method string, payload Obj) (Obj, error) {
	client := &http.Client{Timeout: 2 * callTimout, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}, DisableKeepAlives: true}}
	body, _ := json.Marshal(payload)
	response, err := client.Post("http://control/rpc/"+method, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, &TransportError{Message: fmt.Sprintf("%s: %v", path, err)}
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(response.Body, maxBody))
	document, err := DecodeObj(data)
	if err != nil {
		return nil, &TransportError{Message: "bad reply"}
	}
	switch response.StatusCode {
	case 200:
		return document, nil
	case 409:
		return nil, &Refused{Reason: str(document, "error")}
	}
	return nil, &TransportError{Message: str(document, "error")}
}
