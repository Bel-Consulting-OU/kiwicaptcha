package kiwicaptcha

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// jsonNumber carries a json number as its raw literal text, so an
// encode of a decoded token re-emits the exact wire spelling instead
// of a reformatted float.
type jsonNumber string

// JSONObject is a decoded json object that preserves the wire key
// order. Duplicate keys keep the first position and the last value,
// the same resolution the php json decoder applies.
type JSONObject struct {
	keys   []string
	values map[string]interface{}
}

// Get returns the value stored under the key.
func (o *JSONObject) Get(key string) (interface{}, bool) {
	value, ok := o.values[key]
	return value, ok
}

// Len returns the number of members.
func (o *JSONObject) Len() int { return len(o.keys) }

// Keys returns the members in wire order.
func (o *JSONObject) Keys() []string { return o.keys }

// NewJSONObject builds an object from ordered pairs, the encoder side
// used by native solvers and tests.
func NewJSONObject(pairs ...JSONPair) *JSONObject {
	obj := &JSONObject{values: map[string]interface{}{}}
	for _, pair := range pairs {
		obj.Set(pair.Key, pair.Value)
	}
	return obj
}

// JSONPair is one ordered member of a JSONObject.
type JSONPair struct {
	Key   string
	Value interface{}
}

// Set inserts or updates a member, preserving first position on
// update.
func (o *JSONObject) Set(key string, value interface{}) {
	if _, exists := o.values[key]; !exists {
		o.keys = append(o.keys, key)
	}
	o.values[key] = value
}

// Encode renders the object with the compact separators and the ascii
// escaping of the reference encoders, so a decoded token encodes back
// to its exact wire bytes.
func (o *JSONObject) Encode() string {
	var sb strings.Builder
	sb.WriteByte('{')
	for i, key := range o.keys {
		if i > 0 {
			sb.WriteByte(',')
		}
		writeJSONString(&sb, key)
		sb.WriteByte(':')
		writeJSONValue(&sb, o.values[key])
	}
	sb.WriteByte('}')
	return sb.String()
}

func writeJSONValue(sb *strings.Builder, value interface{}) {
	switch typed := value.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		if typed {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case jsonNumber:
		sb.WriteString(string(typed))
	case string:
		writeJSONString(sb, typed)
	case *JSONObject:
		sb.WriteString(typed.Encode())
	case []interface{}:
		sb.WriteByte('[')
		for i, item := range typed {
			if i > 0 {
				sb.WriteByte(',')
			}
			writeJSONValue(sb, item)
		}
		sb.WriteByte(']')
	default:
		sb.WriteString("null")
	}
}

func writeJSONString(sb *strings.Builder, value string) {
	sb.WriteByte('"')
	for _, runeValue := range value {
		switch runeValue {
		case '"':
			sb.WriteString("\\\"")
		case '\\':
			sb.WriteString("\\\\")
		case '\n':
			sb.WriteString("\\n")
		case '\r':
			sb.WriteString("\\r")
		case '\t':
			sb.WriteString("\\t")
		case '\b':
			sb.WriteString("\\b")
		case '\f':
			sb.WriteString("\\f")
		default:
			if runeValue < 0x20 || runeValue > 0x7e {
				writeEscapedRune(sb, runeValue)
			} else {
				sb.WriteRune(runeValue)
			}
		}
	}
	sb.WriteByte('"')
}

func writeEscapedRune(sb *strings.Builder, runeValue rune) {
	if runeValue > 0xffff {
		high, low := utf16.EncodeRune(runeValue)
		writeUnicodeEscape(sb, high)
		writeUnicodeEscape(sb, low)
		return
	}
	writeUnicodeEscape(sb, runeValue)
}

func writeUnicodeEscape(sb *strings.Builder, unit rune) {
	sb.WriteString("\\u")
	digits := strconv.FormatInt(int64(unit), 16)
	for i := 0; i < 4-len(digits); i++ {
		sb.WriteByte('0')
	}
	sb.WriteString(digits)
}

// parseJSONObject parses one json document that must be an object,
// preserving key order and the raw spelling of every number.
func parseJSONObject(text string) (*JSONObject, error) {
	if !utf8.ValidString(text) {
		return nil, errors.New("kiwicaptcha: telemetry is not valid utf-8")
	}
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	first, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := first.(json.Delim); !ok || delim != '{' {
		return nil, errors.New("kiwicaptcha: telemetry must be a json object")
	}
	obj := &JSONObject{values: map[string]interface{}{}}
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, errors.New("kiwicaptcha: telemetry key is not a string")
		}
		value, err := decodeOrderedValue(dec)
		if err != nil {
			return nil, err
		}
		if _, exists := obj.values[key]; !exists {
			obj.keys = append(obj.keys, key)
		}
		obj.values[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("kiwicaptcha: trailing bytes after the telemetry object")
	}
	return obj, nil
}

func decodeOrderedValue(dec *json.Decoder) (interface{}, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := token.(json.Delim); ok {
		switch delim {
		case '{':
			obj := &JSONObject{values: map[string]interface{}{}}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("kiwicaptcha: telemetry key is not a string")
				}
				value, err := decodeOrderedValue(dec)
				if err != nil {
					return nil, err
				}
				if _, exists := obj.values[key]; !exists {
					obj.keys = append(obj.keys, key)
				}
				obj.values[key] = value
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return obj, nil
		case '[':
			var out []interface{}
			for dec.More() {
				value, err := decodeOrderedValue(dec)
				if err != nil {
					return nil, err
				}
				out = append(out, value)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return out, nil
		}
		return nil, errors.New("kiwicaptcha: unexpected json delimiter")
	}
	if number, ok := token.(json.Number); ok {
		return jsonNumber(number.String()), nil
	}
	return token, nil
}
