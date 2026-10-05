package kiwicaptcha

import (
	"errors"
	"strconv"
	"strings"
)

// Envelope encoding helpers: the stored document is emitted in the
// canonical key order with the compact separators and the ascii
// escaping of the reference writers, so an envelope written by this
// SDK is byte-compatible with the php and Python ones.

func encodeEnvelopeJSON(envelope map[string]interface{}) (string, error) {
	var sb strings.Builder
	sb.WriteByte('{')
	first := true
	emit := func(name string) error {
		value, ok := envelope[name]
		if !ok {
			return nil
		}
		if !first {
			sb.WriteByte(',')
		}
		first = false
		writeJSONString(&sb, name)
		sb.WriteByte(':')
		if err := writeWireValue(&sb, value); err != nil {
			return err
		}
		return nil
	}
	for _, key := range wireKeys {
		if err := emit(key); err != nil {
			return "", err
		}
	}
	for _, key := range []string{"state", "consumed_result", "operation_identity", "resume_owner", "resume_until"} {
		if err := emit(key); err != nil {
			return "", err
		}
	}
	if !first {
		// Every envelope key must come from the fixed orderings above;
		// a foreign key would silently reorder the document.
		for name := range envelope {
			known := false
			for _, key := range wireKeys {
				if key == name {
					known = true
					break
				}
			}
			if !known {
				switch name {
				case "state", "consumed_result", "operation_identity", "resume_owner", "resume_until":
					known = true
				}
			}
			if !known {
				return "", errors.New("kiwicaptcha: envelope carries a key outside the wire schema: " + name)
			}
		}
	}
	sb.WriteByte('}')
	return sb.String(), nil
}

func writeWireValue(sb *strings.Builder, value interface{}) error {
	switch typed := value.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		if typed {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case string:
		writeJSONString(sb, typed)
	case int:
		sb.WriteString(strconv.Itoa(typed))
	case int64:
		sb.WriteString(strconv.FormatInt(typed, 10))
	case jsonNumber:
		sb.WriteString(string(typed))
	default:
		return errors.New("kiwicaptcha: envelope value of unsupported type")
	}
	return nil
}

func encodeJSONString(value string) string {
	var sb strings.Builder
	writeJSONString(&sb, value)
	return sb.String()
}

// errorsAs is a single-error-type unwrap helper, local so the store
// files do not import the errors package twice under two names.
func errorsAs(err error, target **RedisError) bool {
	for err != nil {
		if redisErr, ok := err.(*RedisError); ok {
			*target = redisErr
			return true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapper.Unwrap()
	}
	return false
}
