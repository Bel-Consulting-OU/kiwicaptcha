package kiwicaptcha

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Framework middleware for the net/http stack: one verification
// pipeline the framework adapters for gin, echo, chi and fiber reuse
// (see the integrations directory).
//
// The contract: a request carrying a valid, unconsumed token
// proceeds; anything else is answered with a 403 Forbidden carrying
// the machine-readable error code, and a retry disposition (a storage
// outage or capacity exhaustion) answers with a 503 Service
// Unavailable. Token authority follows the shared rule: every
// non-empty value from the x-kiwi-token header, the kiwi_token form
// field and the kiwi_token query parameter is collected, one distinct
// value verifies, and distinct values in more than one source refuse
// with token_source_conflict before any candidate is verified.

// Middleware constants of the token source order.
const (
	TokenHeader = "X-Kiwi-Token"
	TokenField  = "kiwi_token"
)

// contextKey is the decision context key type.
type contextKey struct{}

// DecisionContextKey is the context key the verified decision is
// stored under.
var DecisionContextKey = contextKey{}

// DecisionFromContext returns the decision a wrapped handler stored,
// when the route ran behind the middleware.
func DecisionFromContext(ctx context.Context) (VerifyDecision, bool) {
	decision, ok := ctx.Value(DecisionContextKey).(VerifyDecision)
	return decision, ok
}

// MiddlewareOptions shapes the net/http middleware.
type MiddlewareOptions struct {
	// SecretKey is the master secret the challenges were signed under.
	SecretKey string
	// ScopePredicate receives the request path without its leading
	// slash and answers whether the route needs a token. Without a
	// predicate every request must carry a token.
	ScopePredicate func(path string) bool
	// Denied overrides the default denial renderer when set.
	Denied func(w http.ResponseWriter, r *http.Request, decision VerifyDecision)
	// TrustedProxies is the trusted-proxy CIDR list (IPv4 and IPv6).
	// The default empty list trusts nobody: X-Forwarded-For and
	// X-Real-IP are ignored and the socket peer is the client IP. With
	// a trusted peer, the forwarded chain is walked right to left
	// through the trusted hops (see ClientIPFromRequest).
	TrustedProxies []string
	// ExecutionPolicy shapes the execution-armed dimension (nil = the
	// fail-closed default; the sidecar policy delegates armed records
	// to a co-located kiwicaptcha-verifier).
	ExecutionPolicy *ExecutionPolicy
}

// Middleware wraps a handler with token verification. The expected
// scope is a required parameter, not an option: the compile-time
// signature makes the empty-scope deployment unrepresentable, matching
// the verifier's typed required_scope refusal.
func Middleware(verifier *Verifier, expectedScope string, opts MiddlewareOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pathScope := strings.Trim(r.URL.Path, "/")
			if pathScope == "" {
				pathScope = "default"
			}
			if opts.ScopePredicate != nil && !opts.ScopePredicate(pathScope) {
				next.ServeHTTP(w, r)
				return
			}
			token, failure := TokenFromRequest(r)
			if failure != "" {
				RenderDenial(w, r, DecisionFromOutcome(InvalidOutcome(failure), ""), opts.Denied)
				return
			}
			outcome := verifier.Verify(token, VerifyOptions{
				SecretKey:       opts.SecretKey,
				ExpectedScope:   expectedScope,
				ClientIP:        ClientIPFromRequest(r, opts.TrustedProxies),
				ExecutionPolicy: opts.ExecutionPolicy,
			})
			mapped := DecisionFromOutcome(outcome, "")
			if mapped.OK {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), DecisionContextKey, mapped)))
				return
			}
			RenderDenial(w, r, mapped, opts.Denied)
		})
	}
}

// RenderDenial writes the framework-idiomatic error: a 403 json body
// with the failure code, or a 503 for a retry disposition.
func RenderDenial(w http.ResponseWriter, r *http.Request, decision VerifyDecision, override func(http.ResponseWriter, *http.Request, VerifyDecision)) {
	if override != nil {
		override(w, r, decision)
		return
	}
	status := http.StatusForbidden
	if decision.Disposition == DispositionRetry {
		status = http.StatusServiceUnavailable
	}
	body, _ := json.Marshal(map[string]interface{}{
		"ok":          false,
		"error":       decision.Error,
		"disposition": decision.Disposition,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// ResolveTokenValues applies the shared token authority rule: every
// non-empty value from every source is collected, one distinct value
// verifies, and two or more distinct values refuse with
// token_source_conflict before any candidate is verified.
func ResolveTokenValues(headerValues, formValues, queryValues []string) (string, VerifyError) {
	token := ""
	seen := make(map[string]bool)
	for _, group := range [][]string{headerValues, formValues, queryValues} {
		for _, value := range group {
			if value == "" || seen[value] {
				continue
			}
			seen[value] = true
			if len(seen) > 1 {
				return "", ErrCodeTokenSourceConflict
			}
			token = value
		}
	}
	if len(seen) == 0 {
		return "", ErrCodeMalformedToken
	}
	return token, ""
}

// TokenFromRequest resolves the token under the shared authority rule
// from the x-kiwi-token header, the kiwi_token form field and the
// kiwi_token query parameter. Repeated header lines, form values and
// query values are all collected. It returns the token and an empty
// failure code, or an empty token and the typed failure code.
func TokenFromRequest(r *http.Request) (string, VerifyError) {
	headerValues := make([]string, 0, 1)
	for _, line := range r.Header.Values(TokenHeader) {
		// A proxy may fold duplicate header lines into one comma list.
		// The token alphabet has no comma, so each entry is a candidate.
		for _, part := range strings.Split(line, ",") {
			if value := strings.TrimSpace(part); value != "" {
				headerValues = append(headerValues, value)
			}
		}
	}
	formValues := []string{}
	if strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") && r.PostForm == nil {
		// Parse the body for the form source; a bad body leaves the
		// field empty.
		_ = r.ParseForm()
	}
	formValues = append(formValues, r.PostForm[TokenField]...)
	queryValues := r.URL.Query()[TokenField]
	return ResolveTokenValues(headerValues, formValues, queryValues)
}

// ClientIPFromRequest resolves the canonical client IP of a request
// against the trusted-proxy CIDR list. An empty list (the default)
// trusts nobody: forwarding headers are ignored and the socket peer is
// the answer, so a client-supplied X-Forwarded-For can never move the
// binding. A trusted peer unlocks the right-to-left forwarded walk and
// the X-Real-IP fallback documented on clientip.go.
func ClientIPFromRequest(r *http.Request, trustedProxies []string) string {
	peer := peerIPText(r)
	prefixes := trustedPrefixes(trustedProxies)
	if len(prefixes) == 0 {
		return peer
	}
	xffLines := r.Header.Values("X-Forwarded-For")
	realIPLines := r.Header.Values("X-Real-IP")
	// A repeated forwarding header is parser ambiguity: one
	// intermediary reads the first line, another the last, so no
	// header-derived identity is trustworthy and the peer wins.
	if len(xffLines) > 1 || len(realIPLines) > 1 {
		return peer
	}
	peerTrusted := peerWithinTrust(peer, prefixes)
	xff := strings.TrimSpace(firstHeaderLine(xffLines))
	if xff == "" {
		if !peerTrusted {
			return peer
		}
		realIP := strings.TrimSpace(firstHeaderLine(realIPLines))
		if realIP == "" || hasControlBytes(realIP) {
			return peer
		}
		if canonical := canonicalIP(realIP); canonical != "" {
			return canonical
		}
		return peer
	}
	if hasControlBytes(xff) || !peerTrusted {
		return peer
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		canonical := canonicalIP(parts[i])
		if canonical == "" {
			// An unparsable hop terminates the trust chain: who lies
			// beyond it cannot be established, so the peer falls
			// back instead of an older attacker-chosen entry.
			return peer
		}
		if !canonicalWithinTrust(canonical, prefixes) {
			return canonical
		}
	}
	return peer
}

// peerIPText extracts the socket peer host from the remote address,
// returned verbatim when it carries no port.
func peerIPText(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// peerWithinTrust reports whether the peer text parses as an address
// inside the trusted prefixes. A peer that is not an IP address is
// never trusted.
func peerWithinTrust(peer string, prefixes []netip.Prefix) bool {
	if peer == "" {
		return false
	}
	addr, err := netip.ParseAddr(strings.Trim(peer, "[]"))
	if err != nil || addr.Zone() != "" {
		return false
	}
	return ipInTrusted(addr, prefixes)
}

// firstHeaderLine returns the first present header line, or an empty
// string when the header is absent.
func firstHeaderLine(lines []string) string {
	for _, line := range lines {
		if line != "" {
			return line
		}
	}
	return ""
}
