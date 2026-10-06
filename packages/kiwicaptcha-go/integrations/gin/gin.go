// Package gin adapts the kiwicaptcha verifier to the gin framework.
// The guard is a gin middleware: it resolves the token from the
// request, verifies it, and on failure aborts with the framework
// idiomatic error json. The verified decision rides the gin context
// under DecisionKey for the handlers downstream.
package gin

import (
	"github.com/gin-gonic/gin"

	kiwi "kiwicaptcha/kiwicaptcha-go"
)

// DecisionKey is the gin context key of the verified decision.
const DecisionKey = "kiwi.decision"

// Middleware builds the gin guard middleware.
func Middleware(verifier *kiwi.Verifier, secretKey, expectedScope string, options ...Option) gin.HandlerFunc {
	config := optionsConfig(options)
	return func(ctx *gin.Context) {
		if config.scopePredicate != nil && !config.scopePredicate(ctx.FullPath()) {
			ctx.Next()
			return
		}
		token := tokenFrom(ctx)
		if token == "" {
			abort(ctx, kiwi.DecisionFromOutcome(kiwi.InvalidOutcome(kiwi.ErrCodeMalformedToken), ""))
			return
		}
		outcome := verifier.Verify(token, kiwi.VerifyOptions{
			SecretKey:     secretKey,
			ExpectedScope: expectedScope,
			ClientIP:      ctx.ClientIP(),
		})
		decision := kiwi.DecisionFromOutcome(outcome, "")
		if decision.OK {
			ctx.Set(DecisionKey, decision)
			ctx.Next()
			return
		}
		abort(ctx, decision)
	}
}

// DecisionFrom returns the decision the guard stored, when the route
// ran behind the middleware.
func DecisionFrom(ctx *gin.Context) (kiwi.VerifyDecision, bool) {
	decision, ok := ctx.Get(DecisionKey)
	if !ok {
		return kiwi.VerifyDecision{}, false
	}
	typed, ok := decision.(kiwi.VerifyDecision)
	return typed, ok
}

type ginConfig struct {
	scopePredicate func(path string) bool
}

// Option shapes the gin guard.
type Option func(*ginConfig)

// WithScopePredicate receives the route pattern and answers whether
// the route needs a token.
func WithScopePredicate(predicate func(path string) bool) Option {
	return func(c *ginConfig) { c.scopePredicate = predicate }
}

func optionsConfig(options []Option) ginConfig {
	config := ginConfig{}
	for _, option := range options {
		option(&config)
	}
	return config
}

func tokenFrom(ctx *gin.Context) string {
	if header := ctx.GetHeader(kiwi.TokenHeader); header != "" {
		return header
	}
	if value, ok := ctx.GetPostForm(kiwi.TokenField); ok && value != "" {
		return value
	}
	return ctx.Query(kiwi.TokenField)
}

func abort(ctx *gin.Context, decision kiwi.VerifyDecision) {
	status := 403
	if decision.Disposition == kiwi.DispositionRetry {
		status = 503
	}
	ctx.AbortWithStatusJSON(status, gin.H{
		"ok":          false,
		"error":       decision.Error,
		"disposition": decision.Disposition,
	})
}
