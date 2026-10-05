package fiber

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"

	kiwi "kiwicaptcha/kiwicaptcha-go"
)

func TestFiberGuard(t *testing.T) {
	verifier := newVerifier(t)
	record := goldenRecordInto(t, verifier)
	app := fiber.New()
	// Fiber v3 registers the handler first and the middleware after;
	// the chain still runs middleware before the handler.
	app.Post("/api/submit", func(ctx fiber.Ctx) error {
		decision, ok := DecisionFrom(ctx)
		if !ok || !decision.OK {
			t.Errorf("the decision must ride the fiber locals")
		}
		return ctx.SendStatus(http.StatusOK)
	}, Middleware(verifier, testSecret, WithExpectedScope("login")))
	// No token: the framework idiomatic denial. fiber.Test drives the
	// app directly and returns the response.
	response, err := app.Test(httptest.NewRequest(http.MethodPost, "/api/submit", nil))
	if err != nil {
		t.Fatalf("fiber test: %v", err)
	}
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("a missing token must deny: %d", response.StatusCode)
	}
	// A solved token proceeds.
	solved := httptest.NewRequest(http.MethodPost, "/api/submit", nil)
	solved.Header.Set("X-Forwarded-For", "198.51.100.7")
	solved.Header.Set(kiwi.TokenHeader, goldenToken(t, record))
	response, err = app.Test(solved)
	if err != nil {
		t.Fatalf("fiber test: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("a solved token must proceed: %d", response.StatusCode)
	}
	// The burned token denies with the consumed code.
	burned := httptest.NewRequest(http.MethodPost, "/api/submit", nil)
	burned.Header.Set("X-Forwarded-For", "198.51.100.7")
	burned.Header.Set(kiwi.TokenHeader, goldenToken(t, record))
	response, err = app.Test(burned)
	if err != nil {
		t.Fatalf("fiber test: %v", err)
	}
	body := make([]byte, 256)
	read, _ := response.Body.Read(body)
	if response.StatusCode != http.StatusForbidden || !strings.Contains(string(body[:read]), "already_consumed") {
		t.Fatalf("a burned token must deny: %d %s", response.StatusCode, string(body[:read]))
	}
}
