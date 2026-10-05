package chi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	kiwi "kiwicaptcha/kiwicaptcha-go"
)

func TestChiRouterGuard(t *testing.T) {
	verifier := newVerifier(t)
	record := goldenRecordInto(t, verifier)
	router := chi.NewRouter()
	router.Use(Middleware(verifier, kiwi.MiddlewareOptions{
		SecretKey:      testSecret,
		ExpectedScope:  "login",
		ScopePredicate: RouteScopePredicate("/api/submit"),
	}))
	router.Get("/public/feed", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	router.Post("/api/submit", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/public/feed", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("an unprotected route must pass: %d", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/submit", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("a protected route must demand a token: %d", recorder.Code)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/submit", nil)
	request.RemoteAddr = "198.51.100.7:41234"
	request.Header.Set(kiwi.TokenHeader, goldenToken(t, record))
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("a solved token must proceed: %d", recorder.Code)
	}
}
