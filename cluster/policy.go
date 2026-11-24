package cluster

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var pcrValue = regexp.MustCompile(`^[0-9a-f]{64}$`)

var requiredPCRs = []int{0, 7, 11}
var optionalPCRs = map[int]string{2: "peripheral_firmware", 3: "eeprom_configuration"}

type Policy struct {
	Allowed map[int][]string
	Images  map[string]string
}

func lowered(values []string) []string {
	seen := map[string]bool{}
	var found []string
	for _, value := range values {
		value = strings.ToLower(value)
		if pcrValue.MatchString(value) && !seen[value] {
			seen[value] = true
			found = append(found, value)
		}
	}
	sort.Strings(found)
	return found
}

func collect(document Obj, section, key string) []string {
	var values []string
	list, _ := document[section].([]any)
	for _, item := range list {
		if entry, ok := item.(Obj); ok {
			values = append(values, fmt.Sprint(valueOr(entry[key], "")))
		}
	}
	return values
}

func valueOr(value any, fallback any) any {
	if value == nil {
		return fallback
	}
	return value
}

func NewPolicy(document Obj) *Policy {
	policy := &Policy{Allowed: map[int][]string{}, Images: map[string]string{}}
	policy.Allowed[0] = lowered(collect(document, "firmware", "pcr0"))
	boot := []string{}
	if secure, ok := document["secure_boot"].(Obj); ok {
		boot = append(boot, fmt.Sprint(valueOr(secure["pcr7"], "")))
	} else {
		boot = append(boot, "")
	}
	boot = append(boot, collect(document, "secure_boot_all", "pcr7")...)
	policy.Allowed[7] = lowered(boot)
	policy.Allowed[11] = lowered(collect(document, "versions", "pcr11"))
	for number, section := range optionalPCRs {
		if values := lowered(collect(document, section, fmt.Sprintf("pcr%d", number))); len(values) > 0 {
			policy.Allowed[number] = values
		}
	}
	versions, _ := document["versions"].([]any)
	for _, item := range versions {
		if entry, ok := item.(Obj); ok {
			policy.Images[strings.ToLower(fmt.Sprint(valueOr(entry["pcr11"], "")))] = fmt.Sprint(valueOr(entry["version"], "None"))
		}
	}
	return policy
}

func (policy *Policy) Check(pcrs map[string]string) (string, error) {
	for _, number := range requiredPCRs {
		if len(policy.Allowed[number]) == 0 {
			return "", fmt.Errorf("the policy accepts no value for PCR %d", number)
		}
	}
	order := []int{0, 7, 11}
	for _, number := range []int{2, 3} {
		if _, present := policy.Allowed[number]; present {
			order = append(order, number)
		}
	}
	for _, number := range order {
		value := strings.ToLower(pcrs[fmt.Sprint(number)])
		if !contains(policy.Allowed[number], value) {
			shown := value
			if len(shown) > 16 {
				shown = shown[:16]
			}
			if shown == "" {
				shown = "missing"
			}
			return "", fmt.Errorf("PCR %d is %s, not one the policy accepts", number, shown)
		}
	}
	return policy.Images[strings.ToLower(pcrs["11"])], nil
}
