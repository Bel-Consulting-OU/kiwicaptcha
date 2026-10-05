package kiwicaptcha

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Strict JSON decoding helpers shared by the record parser and the
// stored envelope decoder. Both surfaces follow the serde deny
// unknown fields rule and reject semantic duplicate keys: a document
// whose members decode to the same name at any nesting level is
// ambiguous corruption and is never trusted.

type strictJSONError struct{ msg string }

func (e *strictJSONError) Error() string { return e.msg }

func strictErrf(format string, args ...interface{}) error {
	return &strictJSONError{msg: fmt.Sprintf(format, args...)}
}

// decodeStrictJSON parses one JSON document into Go values with
// json.Number numbers, rejecting duplicate object keys at every
// nesting level and any trailing bytes after the value.
func decodeStrictJSON(data []byte) (interface{}, error) {
	if len(data) > EnvelopeMaxBytes {
		return nil, strictErrf("document exceeds the %d byte envelope ceiling", EnvelopeMaxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	value, err := decodeStrictValue(dec)
	if err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, strictErrf("trailing bytes after the json value")
	}
	return value, nil
}

func decodeStrictValue(dec *json.Decoder) (interface{}, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	return decodeStrictFromToken(dec, token)
}

func decodeStrictFromToken(dec *json.Decoder, token json.Token) (interface{}, error) {
	switch typed := token.(type) {
	case json.Delim:
		switch typed {
		case '{':
			return decodeStrictObject(dec)
		case '[':
			return decodeStrictArray(dec)
		}
		return nil, strictErrf("unexpected json delimiter %v", typed)
	default:
		return token, nil
	}
}

func decodeStrictObject(dec *json.Decoder) (interface{}, error) {
	seen := map[string]bool{}
	out := map[string]interface{}{}
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, strictErrf("object key is not a string")
		}
		if seen[key] {
			return nil, strictErrf("duplicate json key: %s", key)
		}
		seen[key] = true
		valueToken, err := dec.Token()
		if err != nil {
			return nil, err
		}
		value, err := decodeStrictFromToken(dec, valueToken)
		if err != nil {
			return nil, err
		}
		out[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return out, nil
}

func decodeStrictArray(dec *json.Decoder) (interface{}, error) {
	out := []interface{}{}
	for dec.More() {
		value, err := decodeStrictValue(dec)
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
