package kiwicaptcha

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A minimal Redis client over the Redis wire protocol, implemented on
// the standard library's net and bufio packages only. The client
// speaks RESP2, the protocol the php and Python adapters run over,
// and implements the narrow command surface the store adapter needs:
// get, set with a lifetime, pttl, del, and script execution through
// eval, evalsha and script load. One connection, serialized with a
// mutex; the adapter issues one request at a time.

// RedisError is a negative server reply.
type RedisError struct{ Message string }

func (e *RedisError) Error() string { return "kiwicaptcha: redis error: " + e.Message }

// IsNoScript reports the noscript miss that triggers an eval reload.
func (e *RedisError) IsNoScript() bool {
	message := strings.ToLower(e.Message)
	return strings.Contains(message, "noscript")
}

// RedisReply is one decoded server reply: nil, int64, string,
// RedisError, or []interface{} for arrays.
type RedisReply interface{}

// RedisClient is the narrow command surface the Redis store adapter
// binds to, so tests and deployments can substitute any client with
// the same five verbs.
type RedisClient interface {
	Get(key string) (string, bool, error)
	SetWithTTL(key, value string, ttlMillis int64) error
	Pttl(key string) (int64, error)
	Del(key string) (bool, error)
	Eval(script string, keys, args []string) (RedisReply, error)
	EvalSha(sha string, keys, args []string) (RedisReply, error)
	ScriptLoad(script string) (string, error)
	Close() error
}

// RespClient is the shipped wire protocol client.
type RespClient struct {
	mu     sync.Mutex
	conn   net.Conn
	reader *bufio.Reader
}

// DialRedis builds the shipped client from a redis:// or rediss://
// url. The rediss scheme is accepted but requires a TLS term: this
// client speaks the plaintext protocol only, so a rediss url is
// rejected with a clear error rather than silently downgrading.
func DialRedis(raw string) (*RespClient, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("kiwicaptcha: bad redis url: %w", err)
	}
	if strings.ToLower(parsed.Scheme) == "rediss" {
		return nil, errors.New("kiwicaptcha: rediss:// needs a tls transport this stdlib client does not carry; terminate tls at the redis proxy fronting the store")
	}
	host := parsed.Host
	if host == "" {
		host = "127.0.0.1:6379"
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "6379")
	}
	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("kiwicaptcha: redis dial failed: %w", err)
	}
	if parsed.User != nil {
		if password, ok := parsed.User.Password(); ok {
			client := &RespClient{conn: conn, reader: bufio.NewReader(conn)}
			if _, authErr := client.Command("AUTH", parsed.User.Username(), password); authErr != nil {
				conn.Close()
				return nil, fmt.Errorf("kiwicaptcha: redis auth failed: %w", authErr)
			}
			return client, nil
		}
	}
	return &RespClient{conn: conn, reader: bufio.NewReader(conn)}, nil
}

// Command sends one command and decodes the reply.
func (c *RespClient) Command(args ...string) (RedisReply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.commandLocked(args...)
}

func (c *RespClient) commandLocked(args ...string) (RedisReply, error) {
	if c.conn == nil {
		return nil, errors.New("kiwicaptcha: redis client is closed")
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "*%d\r\n", len(args))
	for _, arg := range args {
		fmt.Fprintf(&sb, "$%d\r\n%s\r\n", len(arg), arg)
	}
	if _, err := c.conn.Write([]byte(sb.String())); err != nil {
		return nil, fmt.Errorf("kiwicaptcha: redis write failed: %w", err)
	}
	return c.readReplyLocked()
}

func (c *RespClient) readReplyLocked() (RedisReply, error) {
	line, err := c.readLineLocked()
	if err != nil {
		return nil, err
	}
	if len(line) == 0 {
		return nil, errors.New("kiwicaptcha: redis sent an empty reply line")
	}
	switch line[0] {
	case '+':
		return line[1:], nil
	case '-':
		// A negative reply surfaces as the typed error.
		return nil, &RedisError{Message: line[1:]}
	case ':':
		value, err := strconv.ParseInt(line[1:], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("kiwicaptcha: bad redis integer reply: %w", err)
		}
		return value, nil
	case '$':
		length, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, fmt.Errorf("kiwicaptcha: bad redis bulk length: %w", err)
		}
		if length < 0 {
			return nil, nil
		}
		payload := make([]byte, length+2)
		if _, err := readFull(c.reader, payload); err != nil {
			return nil, fmt.Errorf("kiwicaptcha: redis bulk read failed: %w", err)
		}
		return string(payload[:length]), nil
	case '*':
		count, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, fmt.Errorf("kiwicaptcha: bad redis array length: %w", err)
		}
		if count < 0 {
			return nil, nil
		}
		out := make([]interface{}, count)
		for i := 0; i < count; i++ {
			item, err := c.readReplyLocked()
			if err != nil {
				return nil, err
			}
			out[i] = item
		}
		return out, nil
	default:
		return nil, fmt.Errorf("kiwicaptcha: unknown redis reply type %q", line[0])
	}
}

func (c *RespClient) readLineLocked() (string, error) {
	line, err := c.reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("kiwicaptcha: redis read failed: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func readFull(reader *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := reader.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// Get returns the string value and its presence.
func (c *RespClient) Get(key string) (string, bool, error) {
	reply, err := c.Command("GET", key)
	if err != nil {
		return "", false, err
	}
	if reply == nil {
		return "", false, nil
	}
	text, ok := reply.(string)
	if !ok {
		return "", false, errors.New("kiwicaptcha: redis get returned a non string reply")
	}
	return text, true, nil
}

// SetWithTTL writes the value with a millisecond lifetime.
func (c *RespClient) SetWithTTL(key, value string, ttlMillis int64) error {
	_, err := c.Command("SET", key, value, "PX", strconv.FormatInt(ttlMillis, 10))
	return err
}

// Pttl returns the remaining lifetime in milliseconds.
func (c *RespClient) Pttl(key string) (int64, error) {
	reply, err := c.Command("PTTL", key)
	if err != nil {
		return 0, err
	}
	value, ok := reply.(int64)
	if !ok {
		return 0, errors.New("kiwicaptcha: redis pttl returned a non integer reply")
	}
	return value, nil
}

// Del removes one key.
func (c *RespClient) Del(key string) (bool, error) {
	reply, err := c.Command("DEL", key)
	if err != nil {
		return false, err
	}
	value, ok := reply.(int64)
	if !ok {
		return false, errors.New("kiwicaptcha: redis del returned a non integer reply")
	}
	return value > 0, nil
}

// Eval runs one script.
func (c *RespClient) Eval(script string, keys, args []string) (RedisReply, error) {
	parts := make([]string, 0, 3+len(keys)+len(args))
	parts = append(parts, "EVAL", script, strconv.Itoa(len(keys)))
	parts = append(parts, keys...)
	parts = append(parts, args...)
	return c.Command(parts...)
}

// EvalSha runs a cached script.
func (c *RespClient) EvalSha(sha string, keys, args []string) (RedisReply, error) {
	parts := make([]string, 0, 3+len(keys)+len(args))
	parts = append(parts, "EVALSHA", sha, strconv.Itoa(len(keys)))
	parts = append(parts, keys...)
	parts = append(parts, args...)
	return c.Command(parts...)
}

// ScriptLoad caches one script and returns its hex digest.
func (c *RespClient) ScriptLoad(script string) (string, error) {
	reply, err := c.Command("SCRIPT", "LOAD", script)
	if err != nil {
		return "", err
	}
	text, ok := reply.(string)
	if !ok {
		return "", errors.New("kiwicaptcha: script load returned a non string reply")
	}
	return text, nil
}

// Ping probes the server.
func (c *RespClient) Ping() error {
	_, err := c.Command("PING")
	return err
}

// Close releases the connection.
func (c *RespClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}
