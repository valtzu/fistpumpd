package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	stdstrings "strings"
	"time"
)

const (
	apiGroup      = "cluster.fistpumpd.example"
	apiVersion    = "v1alpha1"
	apiGroupPath  = "/apis/" + apiGroup + "/" + apiVersion
	roleLabelBase = "role.fistpumpd.example/"
)

type APIMember struct {
	Slot    int
	Addr    string
	Roles   []string
	Facts   Obj
	Image   string
	Healthy bool
}

type APIRole struct {
	Name  string
	Min   int
	Max   *int
	Held  int
	Ready int
}

type APISnapshot struct {
	Topology int
	Members  []APIMember
	Roles    []APIRole
}

type kubeAPI struct{ snapshot func() APISnapshot }

func NewKubeAPI(snapshot func() APISnapshot) http.Handler {
	api := &kubeAPI{snapshot: snapshot}
	mux := http.NewServeMux()
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		write(w, 200, Obj{"kind": "APIVersions", "versions": []any{"v1"}})
	})
	mux.HandleFunc("/api/v1", func(w http.ResponseWriter, r *http.Request) {
		write(w, 200, Obj{"kind": "APIResourceList", "groupVersion": "v1", "resources": []any{}})
	})
	mux.HandleFunc("/apis", func(w http.ResponseWriter, r *http.Request) {
		version := Obj{"groupVersion": apiGroup + "/" + apiVersion, "version": apiVersion}
		write(w, 200, Obj{"kind": "APIGroupList", "apiVersion": "v1", "groups": []any{
			Obj{"name": apiGroup, "versions": []any{version}, "preferredVersion": version},
		}})
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		write(w, 200, Obj{"major": "1", "minor": "0", "gitVersion": "fistpumpd"})
	})
	mux.HandleFunc(apiGroupPath, api.resources)
	mux.HandleFunc(apiGroupPath+"/", api.serve)
	return mux
}

func write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func notFound(w http.ResponseWriter, what string) {
	write(w, 404, Obj{"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "NotFound", "code": 404, "message": what + " not found"})
}

func (api *kubeAPI) resources(w http.ResponseWriter, r *http.Request) {
	verbs := []any{"get", "list"}
	write(w, 200, Obj{"kind": "APIResourceList", "groupVersion": apiGroup + "/" + apiVersion, "resources": []any{
		Obj{"name": "machines", "singularName": "machine", "namespaced": false, "kind": "Machine", "verbs": verbs},
		Obj{"name": "machinesets", "singularName": "machineset", "namespaced": false, "kind": "MachineSet", "verbs": verbs},
	}})
}

func machineName(slot int) string { return fmt.Sprintf("slot-%d", slot) }

func machineObject(member APIMember) Obj {
	labels := Obj{}
	for name, value := range member.Facts {
		labels[name] = displayString(value)
	}
	for _, role := range member.Roles {
		labels[roleLabelBase+role] = ""
	}
	host, _, err := net.SplitHostPort(member.Addr)
	if err != nil {
		host = member.Addr
	}
	phase := "Running"
	if !member.Healthy {
		phase = "Failed"
	}
	return Obj{
		"apiVersion": apiGroup + "/" + apiVersion, "kind": "Machine",
		"metadata": Obj{"name": machineName(member.Slot), "labels": labels},
		"spec":     Obj{"providerID": fmt.Sprintf("fistpumpd://slot/%d", member.Slot)},
		"status": Obj{
			"phase": phase, "addresses": []any{Obj{"type": "InternalIP", "address": host}},
			"roles": toAny(member.Roles), "image": member.Image,
		},
	}
}

func machineSetObject(role APIRole) Obj {
	spec := Obj{"replicas": role.Min}
	if role.Max != nil {
		spec["maxReplicas"] = *role.Max
	}
	return Obj{
		"apiVersion": apiGroup + "/" + apiVersion, "kind": "MachineSet",
		"metadata": Obj{"name": role.Name},
		"spec":     spec,
		"status":   Obj{"replicas": role.Held, "readyReplicas": role.Ready},
	}
}

type table struct {
	columns []string
	rows    [][]any
	names   []string
}

func (t table) render() Obj {
	definitions := []any{}
	for index, name := range t.columns {
		definition := Obj{"name": name, "type": "string"}
		if index == 0 {
			definition["format"] = "name"
		}
		definitions = append(definitions, definition)
	}
	rows := []any{}
	for index, cells := range t.rows {
		rows = append(rows, Obj{"cells": cells, "object": Obj{
			"kind": "PartialObjectMetadata", "apiVersion": "meta.k8s.io/v1", "metadata": Obj{"name": t.names[index]},
		}})
	}
	return Obj{"kind": "Table", "apiVersion": "meta.k8s.io/v1", "columnDefinitions": definitions, "rows": rows}
}

func wantsTable(r *http.Request) bool { return stdstrings.Contains(r.Header.Get("Accept"), "as=Table") }

func (api *kubeAPI) serve(w http.ResponseWriter, r *http.Request) {
	parts := stdstrings.Split(stdstrings.Trim(stdstrings.TrimPrefix(r.URL.Path, apiGroupPath), "/"), "/")
	if r.Method != http.MethodGet {
		write(w, 405, Obj{"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "MethodNotAllowed", "code": 405, "message": "the API is read-only"})
		return
	}
	snapshot := api.snapshot()
	members := append([]APIMember{}, snapshot.Members...)
	sort.Slice(members, func(i, j int) bool { return members[i].Slot < members[j].Slot })
	switch parts[0] {
	case "machines":
		api.machines(w, r, parts[1:], members)
	case "machinesets":
		api.machineSets(w, r, parts[1:], snapshot.Roles)
	default:
		notFound(w, r.URL.Path)
	}
}

func status(member APIMember) string {
	if member.Healthy {
		return "Running"
	}
	return "Failed"
}

func (api *kubeAPI) machines(w http.ResponseWriter, r *http.Request, rest []string, members []APIMember) {
	if len(rest) == 1 {
		for _, member := range members {
			if machineName(member.Slot) != rest[0] {
				continue
			}
			if wantsTable(r) {
				write(w, 200, machineTable([]APIMember{member}).render())
				return
			}
			write(w, 200, machineObject(member))
			return
		}
		notFound(w, "machine "+rest[0])
		return
	}
	if wantsTable(r) {
		write(w, 200, machineTable(members).render())
		return
	}
	items := []any{}
	for _, member := range members {
		items = append(items, machineObject(member))
	}
	write(w, 200, Obj{"apiVersion": apiGroup + "/" + apiVersion, "kind": "MachineList", "metadata": Obj{}, "items": items})
}

func machineTable(members []APIMember) table {
	t := table{columns: []string{"Name", "Address", "Roles", "Status", "Image"}}
	for _, member := range members {
		host, _, err := net.SplitHostPort(member.Addr)
		if err != nil {
			host = member.Addr
		}
		roles := stdstrings.Join(member.Roles, ",")
		if roles == "" {
			roles = "<none>"
		}
		t.names = append(t.names, machineName(member.Slot))
		t.rows = append(t.rows, []any{machineName(member.Slot), host, roles, status(member), member.Image})
	}
	return t
}

func (api *kubeAPI) machineSets(w http.ResponseWriter, r *http.Request, rest []string, roles []APIRole) {
	if len(rest) == 1 {
		for _, role := range roles {
			if role.Name != rest[0] {
				continue
			}
			if wantsTable(r) {
				write(w, 200, machineSetTable([]APIRole{role}).render())
				return
			}
			write(w, 200, machineSetObject(role))
			return
		}
		notFound(w, "machineset "+rest[0])
		return
	}
	if wantsTable(r) {
		write(w, 200, machineSetTable(roles).render())
		return
	}
	items := []any{}
	for _, role := range roles {
		items = append(items, machineSetObject(role))
	}
	write(w, 200, Obj{"apiVersion": apiGroup + "/" + apiVersion, "kind": "MachineSetList", "metadata": Obj{}, "items": items})
}

func machineSetTable(roles []APIRole) table {
	t := table{columns: []string{"Name", "Min", "Max", "Held", "Ready"}}
	for _, role := range roles {
		limit := "unbounded"
		if role.Max != nil {
			limit = fmt.Sprint(*role.Max)
		}
		t.names = append(t.names, role.Name)
		t.rows = append(t.rows, []any{role.Name, fmt.Sprint(role.Min), limit, fmt.Sprint(role.Held), fmt.Sprint(role.Ready)})
	}
	return t
}

func StartKubeAPI(handler http.Handler, bind, certFile, keyFile string, clientCA []byte) (*Server, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(clientCA) {
		return nil, fmt.Errorf("the client CA holds no certificate")
	}
	listener, err := tls.Listen("tcp", bind, &tls.Config{
		Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
	})
	if err != nil {
		return nil, err
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = server.Serve(listener) }()
	return &Server{server: server, listener: listener}, nil
}
