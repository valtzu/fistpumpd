package cluster

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

type Obj = map[string]any

func Decode(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return normalize(value), nil
}

func DecodeObj(data []byte) (Obj, error) {
	value, err := Decode(data)
	if err != nil {
		return nil, err
	}
	object, ok := value.(Obj)
	if !ok {
		return nil, fmt.Errorf("expected an object")
	}
	return object, nil
}

func normalize(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			typed[key] = normalize(item)
		}
		return typed
	case []any:
		for index, item := range typed {
			typed[index] = normalize(item)
		}
		return typed
	case json.Number:
		if integer, err := typed.Int64(); err == nil {
			return int(integer)
		}
		if float, err := typed.Float64(); err == nil {
			return float
		}
		return typed
	}
	return value
}

func Marshal(value any) []byte {
	data, err := Canonical(value)
	if err != nil {
		panic(err)
	}
	return data
}

func asInt(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case float64:
		if typed == float64(int(typed)) {
			return int(typed), true
		}
	case json.Number:
		parsed, err := strconv.Atoi(typed.String())
		return parsed, err == nil
	}
	return 0, false
}

func asString(value any) (string, bool) {
	text, ok := value.(string)
	return text, ok
}

func str(object Obj, key string) string {
	text, _ := object[key].(string)
	return text
}

func integer(object Obj, key string) int {
	number, _ := asInt(object[key])
	return number
}

func object(object Obj, key string) Obj {
	value, _ := object[key].(Obj)
	return value
}

func stringList(value any) []string {
	var found []string
	switch typed := value.(type) {
	case []string:
		return append(found, typed...)
	case []any:
		for _, item := range typed {
			if text, ok := item.(string); ok {
				found = append(found, text)
			}
		}
	}
	return found
}

func toAny(list []string) []any {
	converted := make([]any, len(list))
	for index, item := range list {
		converted[index] = item
	}
	return converted
}
