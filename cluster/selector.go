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

func pythonString(value any) string {
	switch typed := value.(type) {
	case bool:
		if typed {
			return "True"
		}
		return "False"
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		text := strconv.FormatFloat(typed, 'f', -1, 64)
		if typed == float64(int64(typed)) {
			return text + ".0"
		}
		return text
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
			return pythonString(fact) == typed, nil
		}
		operand := strings.TrimSpace(typed[len(operator):])
		if operator == "!=" {
			return pythonString(fact) != operand, nil
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

func Matches(selector, facts Obj) bool {
	for name, expression := range selector {
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
	for name, expression := range object {
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
