package echo

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	kiwi "kiwicaptcha/kiwicaptcha-go"
)

func TestEchoGuard(t *testing.T) {
	verifier := newVerifier(t)
	record := goldenRecordInto(t, verifier)
	router := echo.New()
	router.POST("/api/submit", func(ctx echo.Context) error {
		decision, ok := DecisionFrom(ctx)
		if !ok || !decision.OK {
			t.Errorf("the decision must ride the echo context")
		}
		return ctx.NoContent(http.StatusOK)
	}, Middleware(verifier, testSecret, WithExpectedScope("login")))
	// No token: the framework idiomatic denial.
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/submit", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("a missing token must deny: %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "malformed_token") {
		t.Fatalf("the denial must carry the code: %s", recorder.Body.String())
	}
	// A solved token proceeds.
	request := httptest.NewRequest(http.MethodPost, "/api/submit", nil)
	request.RemoteAddr = "198.51.100.7:41234"
	request.Header.Set(kiwi.TokenHeader, goldenToken(t, record))
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("a solved token must proceed: %d", recorder.Code)
	}
	// The burned token denies with the consumed code.
	request = httptest.NewRequest(http.MethodPost, "/api/submit", nil)
	request.RemoteAddr = "198.51.100.7:41234"
	request.Header.Set(kiwi.TokenHeader, goldenToken(t, record))
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), "already_consumed") {
		t.Fatalf("a burned token must deny: %d %s", recorder.Code, recorder.Body.String())
	}
}
