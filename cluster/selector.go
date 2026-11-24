package cluster

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var operators = []string{">=", "<=", "!=", ">", "<"}
var numberPattern = regexp.MustCompile(`^-?\d+(\.\d+)?$`)
var factName = regexp.MustCompile(`^[a-z0-9-]+$`)

func leadingOperator(text string) string {
	for _, operator := range operators {
		if strings.HasPrefix(text, operator) {
			return operator
		}
	}
	return ""
}

func number(value any) (float64, error) {
	switch typed := value.(type) {
	case bool:
		return 0, fmt.Errorf("%v is not a number", value)
	case int:
		return float64(typed), nil
	case int64:
		return float64(typed), nil
	case float64:
		return typed, nil
	case json.Number:
		return typed.Float64()
	case string:
		trimmed := strings.TrimSpace(typed)
		if numberPattern.MatchString(trimmed) {
			return strconv.ParseFloat(trimmed, 64)
		}
	}
	return 0, fmt.Errorf("%v is not a number", value)
}

func displayString(value any) string {
	switch typed := value.(type) {
	case bool:
		return strconv.FormatBool(typed)
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	}
	return fmt.Sprint(value)
}

func compare(fact, expression any) (bool, error) {
	switch typed := expression.(type) {
	case []any:
		for _, item := range typed {
			if matched, err := compare(fact, item); err == nil && matched {
				return true, nil
			} else if err != nil {
				return false, err
			}
		}
		return false, nil
	case string:
		operator := leadingOperator(typed)
		if operator == "" {
			return displayString(fact) == typed, nil
		}
		operand := strings.TrimSpace(typed[len(operator):])
		if operator == "!=" {
			return displayString(fact) != operand, nil
		}
		left, err := number(fact)
		if err != nil {
			return false, err
		}
		right, err := number(operand)
		if err != nil {
			return false, err
		}
		switch operator {
		case ">=":
			return left >= right, nil
		case "<=":
			return left <= right, nil
		case ">":
			return left > right, nil
		default:
			return left < right, nil
		}
	case bool:
		actual, ok := fact.(bool)
		return ok && actual == typed, nil
	case int, int64, float64, json.Number:
		left, err := number(fact)
		if err != nil {
			return false, err
		}
		right, _ := number(typed)
		return left == right, nil
	}
	return false, fmt.Errorf("unsupported selector value %v", expression)
}

const (
	matchLabels      = "matchLabels"
	matchExpressions = "matchExpressions"
)

func sameValue(fact any, wanted string) bool {
	if displayString(fact) == wanted {
		return true
	}
	left, errLeft := number(fact)
	right, errRight := number(wanted)
	return errLeft == nil && errRight == nil && left == right
}

func inValues(fact any, values []string) bool {
	for _, value := range values {
		if sameValue(fact, value) {
			return true
		}
	}
	return false
}

func matchesExpression(expression Obj, facts Obj) bool {
	fact, present := facts[str(expression, "key")]
	values := stringList(expression["values"])
	switch str(expression, "operator") {
	case "In":
		return present && inValues(fact, values)
	case "NotIn":
		return !present || !inValues(fact, values)
	case "Exists":
		return present
	case "DoesNotExist":
		return !present
	case "Gt", "Lt":
		if !present || len(values) != 1 {
			return false
		}
		left, errLeft := number(fact)
		right, errRight := number(values[0])
		if errLeft != nil || errRight != nil {
			return false
		}
		if str(expression, "operator") == "Gt" {
			return left > right
		}
		return left < right
	}
	return false
}

func Matches(selector, facts Obj) bool {
	if labels, ok := selector[matchLabels].(Obj); ok {
		for name, wanted := range labels {
			fact, present := facts[name]
			if !present || !sameValue(fact, displayString(wanted)) {
				return false
			}
		}
	}
	if list, ok := selector[matchExpressions].([]any); ok {
		for _, item := range list {
			if expression, isObject := item.(Obj); !isObject || !matchesExpression(expression, facts) {
				return false
			}
		}
	}
	for name, expression := range selector {
		if name == matchLabels || name == matchExpressions {
			continue
		}
		fact, present := facts[name]
		if !present {
			return false
		}
		matched, err := compare(fact, expression)
		if err != nil || !matched {
			return false
		}
	}
	return true
}

func ValidateSelector(selector any) error {
	object, ok := selector.(Obj)
	if !ok {
		return fmt.Errorf("a selector is an object")
	}
	if err := validateStructured(object); err != nil {
		return err
	}
	for name, expression := range object {
		if name == matchLabels || name == matchExpressions {
			continue
		}
		if !factName.MatchString(name) {
			return fmt.Errorf("bad fact name %q", name)
		}
		items := []any{expression}
		if list, isList := expression.([]any); isList {
			if len(list) == 0 {
				return fmt.Errorf("%s: empty list", name)
			}
			items = list
		}
		for _, item := range items {
			switch typed := item.(type) {
			case string:
				operator := leadingOperator(typed)
				if operator != "" && operator != "!=" {
					if _, err := number(strings.TrimSpace(typed[len(operator):])); err != nil {
						return err
					}
				}
			case bool, int, int64, float64, json.Number:
			default:
				return fmt.Errorf("%s: unsupported value %v", name, item)
			}
		}
	}
	return nil
}

func validateStructured(selector Obj) error {
	if given, present := selector[matchLabels]; present {
		labels, ok := given.(Obj)
		if !ok {
			return fmt.Errorf("matchLabels maps a fact to a value")
		}
		for name, value := range labels {
			if !factName.MatchString(name) {
				return fmt.Errorf("bad fact name %q", name)
			}
			switch value.(type) {
			case string, bool, int, int64, float64, json.Number:
			default:
				return fmt.Errorf("matchLabels %s: unsupported value %v", name, value)
			}
		}
	}
	if given, present := selector[matchExpressions]; present {
		list, ok := given.([]any)
		if !ok {
			return fmt.Errorf("matchExpressions is a list")
		}
		for _, item := range list {
			expression, isObject := item.(Obj)
			if !isObject || !factName.MatchString(str(expression, "key")) {
				return fmt.Errorf("an expression has a key naming a fact")
			}
			values := stringList(expression["values"])
			switch str(expression, "operator") {
			case "In", "NotIn":
				if len(values) == 0 {
					return fmt.Errorf("%s: In and NotIn need values", str(expression, "key"))
				}
			case "Exists", "DoesNotExist":
				if len(values) != 0 {
					return fmt.Errorf("%s: Exists and DoesNotExist take no values", str(expression, "key"))
				}
			case "Gt", "Lt":
				if len(values) != 1 {
					return fmt.Errorf("%s: Gt and Lt take one number", str(expression, "key"))
				}
				if _, err := number(values[0]); err != nil {
					return err
				}
			default:
				return fmt.Errorf("%s: unknown operator %q", str(expression, "key"), str(expression, "operator"))
			}
		}
	}
	return nil
}
