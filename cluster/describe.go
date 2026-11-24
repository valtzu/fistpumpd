package cluster

import (
	"fmt"
	"sort"
	"strconv"
	stdstrings "strings"
)

func Describe(entry Obj) string {
	body, _ := entry["body"].(Obj)
	switch str(entry, "type") {
	case "admit":
		node, _ := body["node"].(Obj)
		roles := stdstrings.Join(stringList(body["roles"]), ", ")
		if roles == "" {
			roles = "none"
		}
		text := fmt.Sprintf("slot %d admitted at %s with roles %s", integer(entry, "index"), str(node, "addr"), roles)
		if founder, _ := body["founder"].(bool); founder {
			text += " (founder)"
		}
		return text
	case "evict":
		return fmt.Sprintf("slot %d evicted: %s", integer(body, "slot"), str(body, "reason"))
	case "topology":
		return fmt.Sprintf("topology version %d adopted", integer(body, "version"))
	}
	return fmt.Sprintf("reset to slots %v", body["members"])
}

func Summarize(chain *Chain) Obj {
	members := []any{}
	slots := make([]int, 0, len(chain.Members))
	for slot := range chain.Members {
		slots = append(slots, slot)
	}
	sort.Ints(slots)
	for _, slot := range slots {
		member := chain.Members[slot]
		members = append(members, Obj{
			"slot": slot, "addr": member.Addr(), "roles": toAny(member.Roles), "image": str(member.Policy, "image"), "status": member.Status,
		})
	}
	entries := []any{}
	for _, entry := range chain.Entries {
		signers := []string{}
		if signatures, ok := entry["sigs"].(Obj); ok {
			for key := range signatures {
				signers = append(signers, key)
			}
			sort.Slice(signers, func(i, j int) bool {
				a, _ := strconv.Atoi(signers[i])
				b, _ := strconv.Atoi(signers[j])
				return a < b
			})
		} else {
			signers = []string{"build key"}
		}
		entries = append(entries, Obj{"index": entry["index"], "type": entry["type"], "text": Describe(entry), "signers": toAny(signers), "hash": EntryHash(entry)})
	}
	return Obj{"members": members, "entries": entries, "head": chain.Head(), "topology": chain.TopologyVersion()}
}
