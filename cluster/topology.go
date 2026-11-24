package cluster

import (
	"fmt"
	"regexp"
	"sort"
)

var roleName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

type Role struct {
	Name      string
	Selector  Obj
	Min       int
	Max       *int
	Conflicts []string
}

type Topology struct {
	Version   int
	Roles     []Role
	Vips      map[string][]string
	Unmatched string
	Digest    string
	Document  Obj
}

func ParseTopology(document Obj) (*Topology, error) {
	version, ok := asInt(document["version"])
	if _, isBool := document["version"].(bool); !ok || isBool || version < 1 {
		return nil, fmt.Errorf("version is a positive integer")
	}
	list, ok := document["roles"].([]any)
	if !ok || len(list) == 0 {
		return nil, fmt.Errorf("roles is a non-empty list")
	}
	names := map[string]bool{}
	for _, item := range list {
		role, isObject := item.(Obj)
		name, isString := role["name"].(string)
		if !isObject || !isString || !roleName.MatchString(name) || names[name] {
			return nil, fmt.Errorf("role names are unique lower-case words")
		}
		names[name] = true
	}
	topology := &Topology{Version: version, Vips: map[string][]string{}, Unmatched: "admit", Document: document}
	for _, item := range list {
		role, err := parseRole(item.(Obj), names)
		if err != nil {
			return nil, err
		}
		topology.Roles = append(topology.Roles, role)
	}
	if vips, present := document["vips"]; present {
		groups, isObject := vips.(Obj)
		if !isObject {
			return nil, fmt.Errorf("vips maps a group to a list of addresses")
		}
		for group, addresses := range groups {
			if _, isList := addresses.([]any); !isList {
				return nil, fmt.Errorf("vips maps a group to a list of addresses")
			}
			topology.Vips[group] = stringList(addresses)
		}
	}
	if unmatched, present := document["unmatched"]; present {
		text, _ := unmatched.(string)
		if text != "admit" && text != "refuse" {
			return nil, fmt.Errorf("unmatched is admit or refuse")
		}
		topology.Unmatched = text
	}
	digest, err := Digest(document)
	if err != nil {
		return nil, err
	}
	topology.Digest = digest
	return topology, nil
}

func parseRole(role Obj, names map[string]bool) (Role, error) {
	name := str(role, "name")
	for key := range role {
		switch key {
		case "name", "selector", "min", "max", "conflicts":
		default:
			return Role{}, fmt.Errorf("%s: unknown keys [%s]", name, key)
		}
	}
	selector := Obj{}
	if given, present := role["selector"]; present {
		if err := ValidateSelector(given); err != nil {
			return Role{}, fmt.Errorf("%s: %v", name, err)
		}
		selector = given.(Obj)
	}
	low := 0
	if given, present := role["min"]; present {
		number, ok := asInt(given)
		if !ok || number < 0 {
			return Role{}, fmt.Errorf("%s: min and max are counts, max at least min", name)
		}
		low = number
	}
	var high *int
	if given, present := role["max"]; present && given != nil {
		number, ok := asInt(given)
		if !ok || number < max(low, 1) {
			return Role{}, fmt.Errorf("%s: min and max are counts, max at least min", name)
		}
		high = &number
	}
	var conflicts []string
	if given, present := role["conflicts"]; present {
		list, isList := given.([]any)
		if !isList {
			return Role{}, fmt.Errorf("%s: conflicts name other roles of this topology", name)
		}
		for _, item := range list {
			other, _ := item.(string)
			if !names[other] || other == name {
				return Role{}, fmt.Errorf("%s: conflicts name other roles of this topology", name)
			}
			conflicts = append(conflicts, other)
		}
	}
	return Role{Name: name, Selector: selector, Min: low, Max: high, Conflicts: conflicts}, nil
}

func (topology *Topology) conflictsOf(name string) []string {
	for _, role := range topology.Roles {
		if role.Name == name {
			return role.Conflicts
		}
	}
	return nil
}

func contains(list []string, wanted string) bool {
	for _, item := range list {
		if item == wanted {
			return true
		}
	}
	return false
}

func held(members [][]string) map[string]int {
	counts := map[string]int{}
	for _, roles := range members {
		for _, role := range roles {
			counts[role]++
		}
	}
	return counts
}

func (topology *Topology) SelectRoles(facts Obj, members [][]string) []string {
	counts := held(members)
	chosen := []string{}
	for _, role := range topology.Roles {
		if !Matches(role.Selector, facts) {
			continue
		}
		clash := false
		for _, other := range chosen {
			if contains(role.Conflicts, other) || contains(topology.conflictsOf(other), role.Name) {
				clash = true
			}
		}
		if clash {
			continue
		}
		if role.Max != nil && counts[role.Name] >= *role.Max {
			continue
		}
		chosen = append(chosen, role.Name)
	}
	return chosen
}

func (topology *Topology) Unmet(members [][]string) map[string]int {
	counts := held(members)
	missing := map[string]int{}
	for _, role := range topology.Roles {
		if counts[role.Name] < role.Min {
			missing[role.Name] = role.Min - counts[role.Name]
		}
	}
	return missing
}

func (topology *Topology) VipGroups() []string {
	groups := make([]string, 0, len(topology.Vips))
	for group := range topology.Vips {
		groups = append(groups, group)
	}
	sort.Strings(groups)
	return groups
}
