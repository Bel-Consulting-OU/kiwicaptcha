// Package chi adapts the kiwicaptcha net/http middleware to the chi
// router. Chi handlers are plain net/http, so the adapter is the
// standard middleware plus a chi.NewRoute-level helper and the scope
// predicate default of the route pattern.
package chi

import (
	"net/http"
	"strings"

	kiwi "kiwicaptcha/kiwicaptcha-go"
)

// Middleware wraps the router with token verification. The expected
// scope is a required parameter (the compile-time-safe spelling of the
// required_scope contract); the options are the net/http ones; see the
// core package for the token source order and the denial rendering.
func Middleware(verifier *kiwi.Verifier, expectedScope string, options kiwi.MiddlewareOptions) func(http.Handler) http.Handler {
	return kiwi.Middleware(verifier, expectedScope, options)
}

// RouteScopePredicate builds a scope predicate from chi style route
// patterns: the request needs a token when its path matches one of
// the registered patterns, compared by their shared prefix segments.
func RouteScopePredicate(patterns ...string) func(path string) bool {
	return func(path string) bool {
		for _, pattern := range patterns {
			if pathMatchesPattern(path, pattern) {
				return true
			}
		}
		return false
	}
}

func pathMatchesPattern(path, pattern string) bool {
	pathParts := strings.Split(strings.Trim(path, "/"), "/")
	patternParts := strings.Split(strings.Trim(pattern, "/"), "/")
	if len(pathParts) < len(patternParts) {
		return false
	}
	for index, part := range patternParts {
		if strings.HasPrefix(part, "{") {
			continue
		}
		if pathParts[index] != part {
			return false
		}
	}
	return true
}
