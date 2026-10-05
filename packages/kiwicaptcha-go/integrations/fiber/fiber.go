// Package fiber adapts the kiwicaptcha verifier to the fiber
// framework. The guard is a fiber middleware: it resolves the token
// from the request, verifies it, and on failure answers with the
// framework idiomatic error json. The verified decision rides the
// fiber locals under DecisionKey for the handlers downstream.
package fiber

import (
	"github.com/gofiber/fiber/v3"

	kiwi "kiwicaptcha/kiwicaptcha-go"
)

// DecisionKey is the fiber locals key of the verified decision.
const DecisionKey = "kiwi.decision"

// Middleware builds the fiber guard middleware.
func Middleware(verifier *kiwi.Verifier, secretKey string, options ...Option) fiber.Handler {
	config := optionsConfig(options)
	return func(ctx fiber.Ctx) error {
		if config.scopePredicate != nil && !config.scopePredicate(ctx.Route().Path) {
			return ctx.Next()
		}
		token := tokenFrom(ctx)
		if token == "" {
			return abort(ctx, kiwi.DecisionFromOutcome(kiwi.InvalidOutcome(kiwi.ErrCodeMalformedToken), ""))
		}
		outcome := verifier.Verify(token, kiwi.VerifyOptions{
			SecretKey:     secretKey,
			ExpectedScope: config.expectedScope,
			ClientIP:      clientIP(ctx),
		})
		decision := kiwi.DecisionFromOutcome(outcome, "")
		if decision.OK {
			ctx.Locals(DecisionKey, decision)
			return ctx.Next()
		}
		return abort(ctx, decision)
	}
}

// DecisionFrom returns the decision the guard stored, when the route
// ran behind the middleware.
func DecisionFrom(ctx fiber.Ctx) (kiwi.VerifyDecision, bool) {
	decision := ctx.Locals(DecisionKey)
	if decision == nil {
		return kiwi.VerifyDecision{}, false
	}
	typed, ok := decision.(kiwi.VerifyDecision)
	return typed, ok
}

type fiberConfig struct {
	expectedScope  string
	scopePredicate func(path string) bool
}

// Option shapes the fiber guard.
type Option func(*fiberConfig)

// WithExpectedScope pins one scope for every protected route.
func WithExpectedScope(scope string) Option {
	return func(c *fiberConfig) { c.expectedScope = scope }
}

// WithScopePredicate receives the route pattern and answers whether
// the route needs a token.
func WithScopePredicate(predicate func(path string) bool) Option {
	return func(c *fiberConfig) { c.scopePredicate = predicate }
}

func optionsConfig(options []Option) fiberConfig {
	config := fiberConfig{}
	for _, option := range options {
		option(&config)
	}
	return config
}

// clientIP resolves the plain remote host without the port, unless
// the deployment configured a trusted proxy header.
func clientIP(ctx fiber.Ctx) string {
	if forwarded := ctx.Get("X-Forwarded-For"); forwarded != "" {
		return forwarded
	}
	return ctx.IP()
}

func tokenFrom(ctx fiber.Ctx) string {
	if header := ctx.Get(kiwi.TokenHeader); header != "" {
		return header
	}
	if value := ctx.FormValue(kiwi.TokenField); value != "" {
		return value
	}
	return ctx.Query(kiwi.TokenField)
}

func abort(ctx fiber.Ctx, decision kiwi.VerifyDecision) error {
	status := fiber.StatusForbidden
	if decision.Disposition == kiwi.DispositionRetry {
		status = fiber.StatusServiceUnavailable
	}
	return ctx.Status(status).JSON(map[string]interface{}{
		"ok":          false,
		"error":       decision.Error,
		"disposition": decision.Disposition,
	})
}
