package kiwicaptcha

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
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
// Unavailable. The token source order is the x-kiwi-token header,
// then the kiwi_token form field, then the kiwi_token query
// parameter.

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
	// ExpectedScope pins one scope for every protected route; empty
	// accepts any scope.
	ExpectedScope string
	// ScopePredicate receives the request path without its leading
	// slash and answers whether the route needs a token. Without a
	// predicate every request must carry a token.
	ScopePredicate func(path string) bool
	// Denied overrides the default denial renderer when set.
	Denied func(w http.ResponseWriter, r *http.Request, decision VerifyDecision)
	// RealIP trusts the x-forwarded-for header's first hop when true.
	RealIP bool
}

// Middleware wraps a handler with token verification.
func Middleware(verifier *Verifier, opts MiddlewareOptions) func(http.Handler) http.Handler {
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
			token := TokenFromRequest(r)
			if token == "" {
				RenderDenial(w, r, DecisionFromOutcome(InvalidOutcome(ErrCodeMalformedToken), ""), opts.Denied)
				return
			}
			outcome := verifier.Verify(token, VerifyOptions{
				SecretKey:     opts.SecretKey,
				ExpectedScope: opts.ExpectedScope,
				ClientIP:      ClientIPFromRequest(r, opts.RealIP),
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

// TokenFromRequest resolves the token from the header, then the form
// field, then the query parameter.
func TokenFromRequest(r *http.Request) string {
	if header := r.Header.Get(TokenHeader); header != "" {
		return header
	}
	if strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") && r.PostForm == nil {
		// Parse only the body, never the query string, for the form
		// source; a bad body leaves the field empty.
		_ = r.ParseForm()
	}
	if r.PostForm.Get(TokenField) != "" {
		return r.PostForm.Get(TokenField)
	}
	return r.URL.Query().Get(TokenField)
}

// ClientIPFromRequest resolves the client ip: the forwarded header's
// first hop when trusted, else the remote address.
func ClientIPFromRequest(r *http.Request, trustForwarded bool) string {
	if trustForwarded {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			if first := strings.TrimSpace(strings.Split(forwarded, ",")[0]); first != "" {
				return first
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
