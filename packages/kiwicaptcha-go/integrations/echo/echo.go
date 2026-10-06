// Package echo adapts the kiwicaptcha verifier to the echo framework.
// The guard is an echo middleware: it resolves the token from the
// request, verifies it, and on failure returns the framework
// idiomatic error json. The verified decision rides the echo context
// under DecisionKey for the handlers downstream.
package echo

import (
	"net"
	"net/http"

	"github.com/labstack/echo/v4"

	kiwi "kiwicaptcha/kiwicaptcha-go"
)

// DecisionKey is the echo context key of the verified decision.
const DecisionKey = "kiwi.decision"

// Middleware builds the echo guard middleware.
func Middleware(verifier *kiwi.Verifier, secretKey, expectedScope string, options ...Option) echo.MiddlewareFunc {
	config := optionsConfig(options)
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			if config.scopePredicate != nil && !config.scopePredicate(ctx.Path()) {
				return next(ctx)
			}
			token := tokenFrom(ctx)
			if token == "" {
				return abort(ctx, kiwi.DecisionFromOutcome(kiwi.InvalidOutcome(kiwi.ErrCodeMalformedToken), ""))
			}
			outcome := verifier.Verify(token, kiwi.VerifyOptions{
				SecretKey:     secretKey,
				ExpectedScope: expectedScope,
				ClientIP:      clientIP(ctx),
			})
			decision := kiwi.DecisionFromOutcome(outcome, "")
			if decision.OK {
				ctx.Set(DecisionKey, decision)
				return next(ctx)
			}
			return abort(ctx, decision)
		}
	}
}

// DecisionFrom returns the decision the guard stored, when the route
// ran behind the middleware.
func DecisionFrom(ctx echo.Context) (kiwi.VerifyDecision, bool) {
	decision := ctx.Get(DecisionKey)
	if decision == nil {
		return kiwi.VerifyDecision{}, false
	}
	typed, ok := decision.(kiwi.VerifyDecision)
	return typed, ok
}

type echoConfig struct {
	scopePredicate func(path string) bool
}

// Option shapes the echo guard.
type Option func(*echoConfig)

// WithScopePredicate receives the route path and answers whether the
// route needs a token.
func WithScopePredicate(predicate func(path string) bool) Option {
	return func(c *echoConfig) { c.scopePredicate = predicate }
}

func optionsConfig(options []Option) echoConfig {
	config := echoConfig{}
	for _, option := range options {
		option(&config)
	}
	return config
}

func tokenFrom(ctx echo.Context) string {
	if header := ctx.Request().Header.Get(kiwi.TokenHeader); header != "" {
		return header
	}
	if value := ctx.FormValue(kiwi.TokenField); value != "" {
		return value
	}
	return ctx.QueryParam(kiwi.TokenField)
}

func clientIP(ctx echo.Context) string {
	if forwarded := ctx.Request().Header.Get("X-Forwarded-For"); forwarded != "" {
		return forwarded
	}
	host, _, err := net.SplitHostPort(ctx.Request().RemoteAddr)
	if err != nil {
		return ctx.Request().RemoteAddr
	}
	return host
}

func abort(ctx echo.Context, decision kiwi.VerifyDecision) error {
	status := http.StatusForbidden
	if decision.Disposition == kiwi.DispositionRetry {
		status = http.StatusServiceUnavailable
	}
	return ctx.JSON(status, map[string]interface{}{
		"ok":          false,
		"error":       decision.Error,
		"disposition": decision.Disposition,
	})
}
