package cluster

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleSnapshot() APISnapshot {
	three := 3
	return APISnapshot{
		Topology: 2,
		Members: []APIMember{
			{Slot: 1, Addr: "192.168.1.7:17947", Roles: []string{"server"}, Facts: Obj{"arch": "arm64", "memory-gib": 8}, Image: "33", Healthy: false},
			{Slot: 0, Addr: "192.168.1.9:17947", Roles: []string{"server", "ingress"}, Facts: Obj{"arch": "arm64"}, Image: "33", Healthy: true},
		},
		Roles: []APIRole{{Name: "server", Min: 3, Max: &three, Held: 2, Ready: 1}, {Name: "ingress", Held: 1, Ready: 1}},
	}
}

func get(t *testing.T, handler http.Handler, path, accept string) (int, Obj) {
	t.Helper()
	request := httptest.NewRequest("GET", path, nil)
	if accept != "" {
		request.Header.Set("Accept", accept)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	var body Obj
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	return recorder.Code, body
}

func TestTheAPIAnswersDiscovery(t *testing.T) {
	handler := NewKubeAPI(sampleSnapshot)
	if code, body := get(t, handler, "/apis", ""); code != 200 || body["kind"] != "APIGroupList" {
		t.Fatalf("%d %v", code, body)
	}
	code, body := get(t, handler, apiGroupPath, "")
	resources, _ := body["resources"].([]any)
	if code != 200 || len(resources) != 2 {
		t.Fatalf("%d %v", code, body)
	}
}

func TestMachinesAreListedInSlotOrderWithLabels(t *testing.T) {
	handler := NewKubeAPI(sampleSnapshot)
	code, body := get(t, handler, apiGroupPath+"/machines", "")
	items, _ := body["items"].([]any)
	if code != 200 || len(items) != 2 {
		t.Fatalf("%d %v", code, body)
	}
	first := items[0].(map[string]any)
	if first["metadata"].(map[string]any)["name"] != "slot-0" {
		t.Fatalf("not in slot order: %v", first)
	}
	second := items[1].(map[string]any)
	labels := second["metadata"].(map[string]any)["labels"].(map[string]any)
	if labels["arch"] != "arm64" || labels["memory-gib"] != "8" {
		t.Fatalf("facts are labels: %v", labels)
	}
	if _, has := labels[roleLabelBase+"server"]; !has {
		t.Fatalf("roles are labels: %v", labels)
	}
	if second["status"].(map[string]any)["phase"] != "Failed" {
		t.Fatalf("a failing member is Failed: %v", second["status"])
	}
}

func TestOneMachineAndOneMachineSet(t *testing.T) {
	handler := NewKubeAPI(sampleSnapshot)
	if code, body := get(t, handler, apiGroupPath+"/machines/slot-1", ""); code != 200 || body["kind"] != "Machine" {
		t.Fatalf("%d %v", code, body)
	}
	if code, _ := get(t, handler, apiGroupPath+"/machines/slot-9", ""); code != 404 {
		t.Fatalf("unknown machine: %d", code)
	}
	code, body := get(t, handler, apiGroupPath+"/machinesets/server", "")
	status := body["status"].(map[string]any)
	if code != 200 || status["replicas"].(float64) != 2 || status["readyReplicas"].(float64) != 1 {
		t.Fatalf("%d %v", code, body)
	}
}

func TestATableIsServedWhenKubectlAsksForOne(t *testing.T) {
	handler := NewKubeAPI(sampleSnapshot)
	code, body := get(t, handler, apiGroupPath+"/machines", "application/json;as=Table;v=v1;g=meta.k8s.io")
	rows, _ := body["rows"].([]any)
	if code != 200 || body["kind"] != "Table" || len(rows) != 2 {
		t.Fatalf("%d %v", code, body)
	}
	cells := rows[0].(map[string]any)["cells"].([]any)
	if cells[0] != "slot-0" || cells[1] != "192.168.1.9" || cells[2] != "server,ingress" || cells[3] != "Running" {
		t.Fatalf("cells %v", cells)
	}
}

func TestTheAPIIsReadOnly(t *testing.T) {
	recorder := httptest.NewRecorder()
	NewKubeAPI(sampleSnapshot).ServeHTTP(recorder, httptest.NewRequest("DELETE", apiGroupPath+"/machines/slot-0", nil))
	if recorder.Code != 405 {
		t.Fatalf("%d", recorder.Code)
	}
}

func issue(t *testing.T, template, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := x509.ParseCertificate(der)
	return parsed, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestOnlyAClientWithACertificateFromTheCAIsServed(t *testing.T) {
	dir := t.TempDir()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	ca, caKey, caPEM := issue(t, caTemplate, nil, nil)
	clientTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "me"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	_, clientKey, clientPEM := issue(t, clientTemplate, ca, caKey)
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "node"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: nil}
	_, serverKey, serverPEM := issue(t, serverTemplate, nil, nil)
	serverKeyDER, _ := x509.MarshalECPrivateKey(serverKey)
	clientKeyDER, _ := x509.MarshalECPrivateKey(clientKey)
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	_ = os.WriteFile(certFile, serverPEM, 0o600)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER}), 0o600)
	server, err := StartKubeAPI(NewKubeAPI(sampleSnapshot), "127.0.0.1:0", certFile, keyFile, caPEM)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Stop()
	url := "https://127.0.0.1:" + strings.TrimPrefix(server.listener.Addr().String(), "127.0.0.1:") + apiGroupPath + "/machines"
	pair, err := tls.X509KeyPair(clientPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyDER}))
	if err != nil {
		t.Fatal(err)
	}
	client := func(certificates []tls.Certificate) *http.Client {
		return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, Certificates: certificates}}}
	}
	if response, err := client(nil).Get(url); err == nil {
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		t.Fatal("a client without a certificate must be refused")
	}
	response, err := client([]tls.Certificate{pair}).Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("status %d", response.StatusCode)
	}
}
