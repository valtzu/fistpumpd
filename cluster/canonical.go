package cluster

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf8"
)

func Canonical(value any) ([]byte, error) {
	var buffer bytes.Buffer
	if err := encode(&buffer, value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func Digest(value any) (string, error) {
	data, err := Canonical(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func encode(buffer *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		buffer.WriteString("null")
	case bool:
		buffer.WriteString(strconv.FormatBool(typed))
	case string:
		return encodeString(buffer, typed)
	case int:
		buffer.WriteString(strconv.Itoa(typed))
	case int64:
		buffer.WriteString(strconv.FormatInt(typed, 10))
	case float64:
		if typed != float64(int64(typed)) {
			return fmt.Errorf("canonical form has no fractions: %v", typed)
		}
		buffer.WriteString(strconv.FormatInt(int64(typed), 10))
	case json.Number:
		if _, err := typed.Int64(); err != nil {
			return fmt.Errorf("canonical form has only integers: %s", typed)
		}
		buffer.WriteString(typed.String())
	case []string:
		return encode(buffer, toAny(typed))
	case []any:
		buffer.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				buffer.WriteByte(',')
			}
			if err := encode(buffer, item); err != nil {
				return err
			}
		}
		buffer.WriteByte(']')
	case map[string]string:
		converted := Obj{}
		for key, item := range typed {
			converted[key] = item
		}
		return encode(buffer, converted)
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buffer.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				buffer.WriteByte(',')
			}
			if err := encodeString(buffer, key); err != nil {
				return err
			}
			buffer.WriteByte(':')
			if err := encode(buffer, typed[key]); err != nil {
				return err
			}
		}
		buffer.WriteByte('}')
	default:
		return fmt.Errorf("canonical form does not know %T", value)
	}
	return nil
}

func encodeString(buffer *bytes.Buffer, text string) error {
	if !utf8.ValidString(text) {
		return fmt.Errorf("canonical strings are valid UTF-8")
	}
	buffer.WriteByte('"')
	for _, character := range text {
		switch character {
		case '"':
			buffer.WriteString(`\"`)
		case '\\':
			buffer.WriteString(`\\`)
		case '\n':
			buffer.WriteString(`\n`)
		case '\r':
			buffer.WriteString(`\r`)
		case '\t':
			buffer.WriteString(`\t`)
		case '\b':
			buffer.WriteString(`\b`)
		case '\f':
			buffer.WriteString(`\f`)
		default:
			if character < 0x20 {
				fmt.Fprintf(buffer, `\u%04x`, character)
			} else {
				buffer.WriteRune(character)
			}
		}
	}
	buffer.WriteByte('"')
	return nil
}
