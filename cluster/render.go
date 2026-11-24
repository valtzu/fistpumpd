package cluster

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	stdstrings "strings"
	"text/template"
)

const runPrefix = "/run/fistpumpd/"

type FileSpec struct {
	Path     string
	Mode     os.FileMode
	Roles    []string
	Template *template.Template
	Reload   string
	Start    string
	Stop     string
}

var templateFunctions = template.FuncMap{
	"priority": Priority,
	"add":      func(a, b int) int { return a + b },
	"mul":      func(a, b int) int { return a * b },
	"upper":    stdstrings.ToUpper,
	"join":     stdstrings.Join,
	"dict": func(pairs ...string) map[string]string {
		result := map[string]string{}
		for index := 0; index+1 < len(pairs); index += 2 {
			result[pairs[index]] = pairs[index+1]
		}
		return result
	},
}

func parseFiles(given any) ([]FileSpec, error) {
	list, isList := given.([]any)
	if !isList {
		return nil, fmt.Errorf("files is a list")
	}
	var files []FileSpec
	seen := map[string]bool{}
	for _, item := range list {
		entry, isObject := item.(Obj)
		if !isObject {
			return nil, fmt.Errorf("a file is an object")
		}
		for key := range entry {
			switch key {
			case "path", "mode", "roles", "template", "reload", "start", "stop":
			default:
				return nil, fmt.Errorf("file: unknown key %s", key)
			}
		}
		path := str(entry, "path")
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || seen[path] {
			return nil, fmt.Errorf("file paths are unique clean absolute paths")
		}
		seen[path] = true
		mode := os.FileMode(0o644)
		if text := str(entry, "mode"); text != "" {
			number, err := strconv.ParseUint(text, 8, 32)
			if err != nil || number > 0o777 {
				return nil, fmt.Errorf("%s: mode is an octal string", path)
			}
			mode = os.FileMode(number)
		}
		compiled, err := template.New(path).Option("missingkey=error").Funcs(templateFunctions).Parse(str(entry, "template"))
		if err != nil {
			return nil, fmt.Errorf("%s: %v", path, err)
		}
		files = append(files, FileSpec{
			Path: path, Mode: mode, Roles: stringList(entry["roles"]), Template: compiled,
			Reload: str(entry, "reload"), Start: str(entry, "start"), Stop: str(entry, "stop"),
		})
	}
	return files, nil
}

type View struct {
	Slot          int
	Rank          int
	Members       int
	MinMembers    int
	Roles         []string
	Topology      int
	Interface     string
	topology      *Topology
	holders       map[string][]int
	first         map[string]int
	CreatesTokens bool
	NeedsTokens   []string
}

func (view *View) Holds(role string) bool { return contains(view.Roles, role) }

func (view *View) Count(role string) int { return len(view.holders[role]) }

func (view *View) RankIn(role string) int {
	for position, holder := range view.holders[role] {
		if holder == view.Slot {
			return position
		}
	}
	return 0
}

func (view *View) IsFirst(role string) bool {
	slot, present := view.first[role]
	return present && slot == view.Slot
}

func (view *View) Vips(group string) []string {
	return append([]string{}, view.topology.Vips[group]...)
}

func (view *View) VipGroups() []string { return view.topology.VipGroups() }

func (view *View) render(spec FileSpec) (string, error) {
	var buffer bytes.Buffer
	if err := spec.Template.Execute(&buffer, view); err != nil {
		return "", fmt.Errorf("%s: %v", spec.Path, err)
	}
	return buffer.String(), nil
}

func (spec FileSpec) applies(view *View) bool {
	if len(spec.Roles) == 0 {
		return true
	}
	for _, role := range spec.Roles {
		if view.Holds(role) {
			return true
		}
	}
	return false
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

func firstSlots(chain *Chain) map[string]int {
	first := map[string]int{}
	slots := make([]int, 0, len(chain.Members))
	for slot := range chain.Members {
		slots = append(slots, slot)
	}
	sort.Ints(slots)
	for _, slot := range slots {
		for _, role := range chain.Members[slot].Roles {
			if _, seen := first[role]; !seen {
				first[role] = slot
			}
		}
	}
	return first
}

func BuildView(chain *Chain, slot int, topology *Topology, minMembers int, iface string) *View {
	me := chain.Member(slot)
	active := chain.Active()
	view := &View{
		Slot: slot, Rank: chain.RankOf(slot), Members: len(active), MinMembers: minMembers, Roles: me.Roles,
		Topology: chain.TopologyVersion(), Interface: iface, topology: topology,
		holders: map[string][]int{}, first: firstSlots(chain),
	}
	for _, member := range active {
		for _, role := range member.Roles {
			view.holders[role] = append(view.holders[role], member.Slot)
		}
	}
	isServer := view.Holds("server")
	isAgent := view.Holds("agent") && !isServer
	init, hasInit := view.first["server"]
	view.CreatesTokens = isServer && hasInit && slot == init
	if isServer && !view.CreatesTokens {
		view.NeedsTokens = append(view.NeedsTokens, "server")
	}
	if isAgent || (isServer && !view.CreatesTokens) {
		view.NeedsTokens = append(view.NeedsTokens, "agent")
	}
	return view
}
