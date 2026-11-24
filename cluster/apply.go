package cluster

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	stdstrings "strings"
)

const APIPort = 6443

var checks = map[string]string{
	"server":  `script "/usr/bin/curl --silent --insecure --max-time 2 --output /dev/null https://127.0.0.1:6443/livez"`,
	"ingress": `script "/usr/bin/curl --silent --max-time 2 --output /dev/null http://127.0.0.1:80/"`,
}

const keepalivedGlobals = "global_defs {\n    enable_script_security\n    script_user nobody\n}\n"

var appended = map[string]bool{"tls-san": true}

type Instance struct {
	Name     string
	RouterID int
	Address  string
	Priority int
	Check    string
}

type KV struct {
	Key   string
	Value any
}

type Plan struct {
	Slot          int
	Rank          int
	Members       int
	Roles         []string
	Topology      int
	Interface     string
	Instances     []Instance
	K3s           []KV
	StartK3s      bool
	CreatesTokens bool
	NeedsTokens   []string
}

func holders(chain *Chain, role string) []int {
	var slots []int
	for _, member := range chain.Active() {
		if contains(member.Roles, role) {
			slots = append(slots, member.Slot)
		}
	}
	return slots
}

func Priority(rank, count, index int) int {
	if count < 1 {
		count = 1
	}
	step := 90 / count
	if step > 10 {
		step = 10
	}
	if step < 1 {
		step = 1
	}
	offset := ((rank-index)%count + count) % count
	return max(1, 100-offset*step)
}

func FirstServerSlot(chain *Chain) int {
	first := -1
	for slot, member := range chain.Members {
		if contains(member.Roles, "server") && (first < 0 || slot < first) {
			first = slot
		}
	}
	return first
}

func BuildPlan(chain *Chain, slot int, topology *Topology, minMembers int, iface string) *Plan {
	me := chain.Member(slot)
	roles := me.Roles
	active := chain.Active()
	plan := &Plan{Slot: slot, Rank: chain.RankOf(slot), Members: len(active), Roles: roles, Topology: chain.TopologyVersion(), Interface: iface}
	for groupIndex, role := range topology.VipGroups() {
		addresses := topology.Vips[role]
		if !contains(roles, role) {
			continue
		}
		if _, known := checks[role]; !known {
			continue
		}
		group := holders(chain, role)
		rank := 0
		for position, holder := range group {
			if holder == slot {
				rank = position
			}
		}
		for index, address := range addresses {
			plan.Instances = append(plan.Instances, Instance{
				Name: fmt.Sprintf("%s%d", stdstrings.ToUpper(role), index+1), RouterID: 60 + 10*groupIndex + index,
				Address: address, Priority: Priority(rank, len(group), index), Check: role,
			})
		}
	}
	api := ""
	if servers := topology.Vips["server"]; len(servers) > 0 {
		api = servers[0]
	}
	init := FirstServerSlot(chain)
	isServer := contains(roles, "server")
	isAgent := contains(roles, "agent") && !isServer
	ready := len(active) >= minMembers
	if isServer {
		plan.K3s = append(plan.K3s, KV{"tls-san", append([]string{}, topology.Vips["server"]...)})
		if slot == init {
			plan.K3s = append(plan.K3s, KV{"cluster-init", true})
		} else if api != "" {
			plan.K3s = append(plan.K3s, KV{"server", fmt.Sprintf("https://%s:%d", api, APIPort)})
		}
	} else if isAgent && api != "" {
		plan.K3s = append(plan.K3s, KV{"server", fmt.Sprintf("https://%s:%d", api, APIPort)})
	}
	plan.StartK3s = (isServer || isAgent) && ready && (slot == init || api != "")
	plan.CreatesTokens = isServer && slot == init
	if isServer && slot != init {
		plan.NeedsTokens = append(plan.NeedsTokens, "server")
	}
	if isAgent || (isServer && slot != init) {
		plan.NeedsTokens = append(plan.NeedsTokens, "agent")
	}
	return plan
}

func RenderKeepalived(plan *Plan) string {
	blocks := []string{keepalivedGlobals}
	kinds := map[string]bool{}
	for _, instance := range plan.Instances {
		kinds[instance.Check] = true
	}
	names := make([]string, 0, len(kinds))
	for kind := range kinds {
		names = append(names, kind)
	}
	sort.Strings(names)
	for _, kind := range names {
		blocks = append(blocks, fmt.Sprintf("vrrp_script chk_%s {\n    %s\n    interval 2\n    fall 2\n    rise 2\n}\n", kind, checks[kind]))
	}
	for _, instance := range plan.Instances {
		blocks = append(blocks, fmt.Sprintf("vrrp_instance %s {\n    interface %s\n    state BACKUP\n    virtual_router_id %d\n    advert_int 1\n    preempt_delay 60\n    priority %d\n    virtual_ipaddress {\n        %s/24\n    }\n    track_script {\n        chk_%s\n    }\n}\n",
			instance.Name, plan.Interface, instance.RouterID, instance.Priority, instance.Address, instance.Check))
	}
	return stdstrings.Join(blocks, "\n")
}

func RenderK3s(settings []KV) string {
	var lines []string
	for _, pair := range settings {
		switch value := pair.Value.(type) {
		case []string:
			if len(value) == 0 {
				continue
			}
			key := pair.Key + ":"
			if appended[pair.Key] {
				key = pair.Key + "+:"
			}
			lines = append(lines, key)
			for _, item := range value {
				lines = append(lines, "  - "+item)
			}
		case bool:
			lines = append(lines, fmt.Sprintf("%s: %t", pair.Key, value))
		default:
			lines = append(lines, fmt.Sprintf("%s: %v", pair.Key, value))
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return stdstrings.Join(lines, "\n") + "\n"
}

func writeIfChanged(path, content string, mode os.FileMode) (bool, error) {
	if existing, err := os.ReadFile(path); err == nil && string(existing) == content {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	return true, writeAtomic(path, []byte(content), mode)
}

func removeFile(path string) bool { return os.Remove(path) == nil }

type Host interface {
	Run(name string, arguments ...string)
}

type SystemHost struct{}

func (SystemHost) Run(name string, arguments ...string) {
	_ = exec.Command(name, arguments...).Run()
}

func Apply(plan *Plan, root, runDirectory string, host Host) ([]string, error) {
	var changed []string
	state := Marshal(Obj{"slot": plan.Slot, "rank": plan.Rank, "members": plan.Members, "roles": plan.Roles, "topology": plan.Topology, "start_k3s": plan.StartK3s})
	if _, err := writeIfChanged(filepath.Join(runDirectory, "state.json"), string(state)+"\n", 0o644); err != nil {
		return changed, err
	}
	markers := filepath.Join(root, "etc/node-role.d")
	if entries, err := os.ReadDir(markers); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if stdstrings.HasSuffix(name, ".conf") && !contains(plan.Roles, stdstrings.TrimSuffix(name, ".conf")) {
				_ = os.Remove(filepath.Join(markers, name))
			}
		}
	}
	rolesChanged := false
	for _, role := range plan.Roles {
		updated, err := writeIfChanged(filepath.Join(markers, role+".conf"), "ROLE="+role+"\n", 0o644)
		if err != nil {
			return changed, err
		}
		rolesChanged = rolesChanged || updated
	}
	if rolesChanged {
		changed = append(changed, "roles")
		host.Run("hostnamectl", append([]string{"tags"}, plan.Roles...)...)
		host.Run("systemctl", "start", "systemd-sysupdate-auto-enable.service")
	}
	config := filepath.Join(runDirectory, "keepalived.conf")
	if len(plan.Instances) > 0 {
		if updated, err := writeIfChanged(config, RenderKeepalived(plan), 0o644); err != nil {
			return changed, err
		} else if updated {
			host.Run("systemctl", "reload-or-restart", "keepalived.service")
		}
	} else if removeFile(config) {
		host.Run("systemctl", "stop", "keepalived.service")
	}
	dropin := filepath.Join(root, "etc/rancher/k3s/config.yaml.d/10-role.yaml")
	if len(plan.K3s) > 0 {
		if _, err := writeIfChanged(dropin, RenderK3s(plan.K3s), 0o644); err != nil {
			return changed, err
		}
	} else {
		removeFile(dropin)
	}
	ready := filepath.Join(runDirectory, "k3s-ready")
	if plan.StartK3s {
		if updated, err := writeIfChanged(ready, "ready\n", 0o644); err != nil {
			return changed, err
		} else if updated {
			host.Run("systemctl", "start", "--no-block", "k3s.service")
		}
	} else {
		removeFile(ready)
	}
	return changed, nil
}
