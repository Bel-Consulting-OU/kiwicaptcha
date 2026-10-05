package kiwicaptcha

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newMiddlewareStack(t *testing.T, options MiddlewareOptions) (*Verifier, http.Handler, *int) {
	t.Helper()
	verifier := newTestVerifier(t, VerifierConfig{}, goldenIssuedAt)
	calls := 0
	handler := Middleware(verifier, options)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	return verifier, handler, &calls
}

func goldenLiveToken(t *testing.T) string {
	t.Helper()
	record := goldenRecord(t, "golden_sha256_v2.json")
	return CreateToken(record.Nonce, solveSha(record.Prefix, record.Salt, record.TargetBits), 5000, NewJSONObject(), "", "", "").Encode()
}

// goldenIPRequest builds a request from the golden record's bound ip,
// so the ip binding passes.
func goldenIPRequest(method, target string, body io.Reader) *http.Request {
	request := httptest.NewRequest(method, target, body)
	request.RemoteAddr = "198.51.100.7:41234"
	return request
}

func goldenLiveRecordInto(t *testing.T, verifier *Verifier) *ChallengeRecord {
	t.Helper()
	record := goldenRecord(t, "golden_sha256_v2.json")
	storeRecord(t, verifier.Storage, record)
	return record
}

func TestMiddlewareAllowsValidToken(t *testing.T) {
	verifier := newTestVerifier(t, VerifierConfig{}, goldenIssuedAt)
	goldenLiveRecordInto(t, verifier)
	proceeded := false
	handler := Middleware(verifier, MiddlewareOptions{
		SecretKey:     testSecret,
		ExpectedScope: "login",
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proceeded = true
		decision, ok := DecisionFromContext(r.Context())
		if !ok || !decision.OK {
			t.Errorf("the verified decision must ride the context")
		}
	}))
	request := goldenIPRequest(http.MethodPost, "/api/submit", nil)
	request.Header.Set(TokenHeader, goldenLiveToken(t))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !proceeded {
		t.Fatalf("a valid token must proceed: %d", recorder.Code)
	}
}

func TestMiddlewareDeniesWithoutToken(t *testing.T) {
	_, handler, calls := newMiddlewareStack(t, MiddlewareOptions{SecretKey: testSecret})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/submit", nil))
	if recorder.Code != http.StatusForbidden || *calls != 0 {
		t.Fatalf("a missing token must deny with 403: %d calls=%d", recorder.Code, *calls)
	}
	if !strings.Contains(recorder.Body.String(), `"error":"malformed_token"`) {
		t.Fatalf("the denial must carry the machine-readable code: %s", recorder.Body.String())
	}
	if recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("the denial is json")
	}
}

func TestMiddlewareDeniesBadToken(t *testing.T) {
	verifier, handler, calls := newMiddlewareStack(t, MiddlewareOptions{SecretKey: testSecret})
	goldenLiveRecordInto(t, verifier)
	request := goldenIPRequest(http.MethodPost, "/api/submit", nil)
	request.Header.Set(TokenHeader, goldenLiveToken(t))
	handler.ServeHTTP(httptest.NewRecorder(), request)
	// The token is now burned; a replay denies.
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden || *calls != 1 {
		t.Fatalf("a burned token must deny: %d calls=%d", recorder.Code, *calls)
	}
	if !strings.Contains(recorder.Body.String(), "already_consumed") {
		t.Fatalf("the replay denial must carry the code: %s", recorder.Body.String())
	}
}

func TestMiddlewareRetryAnswers503(t *testing.T) {
	verifier := newTestVerifier(t, VerifierConfig{}, testNow)
	verifier.Storage = failingStore{}
	handler := Middleware(verifier, MiddlewareOptions{
		SecretKey:     testSecret,
		ExpectedScope: "login",
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	// A structurally valid token reaches the store, which is down.
	wellFormed := CreateToken(goldenRecord(t, "golden_sha256_v2.json").Nonce, 1, 5000, NewJSONObject(), "", "", "").Encode()
	request := goldenIPRequest(http.MethodPost, "/api/submit", nil)
	request.Header.Set(TokenHeader, wellFormed)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("a storage outage must answer 503: %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), `"disposition":"retry"`) {
		t.Fatalf("the retry disposition must surface: %s", recorder.Body.String())
	}
}

func TestMiddlewareTokenSources(t *testing.T) {
	token := goldenLiveToken(t)
	t.Run("form field", func(t *testing.T) {
		verifier, handler, calls := newMiddlewareStack(t, MiddlewareOptions{SecretKey: testSecret})
		goldenLiveRecordInto(t, verifier)
		form := url.Values{}
		form.Set(TokenField, token)
		request := goldenIPRequest(http.MethodPost, "/api/submit", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK || *calls != 1 {
			t.Fatalf("the form source must work: %d", recorder.Code)
		}
	})
	t.Run("query parameter", func(t *testing.T) {
		verifier, handler, calls := newMiddlewareStack(t, MiddlewareOptions{SecretKey: testSecret})
		goldenLiveRecordInto(t, verifier)
		request := goldenIPRequest(http.MethodGet, "/api/submit?"+url.Values{TokenField: {token}}.Encode(), nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK || *calls != 1 {
			t.Fatalf("the query source must work: %d", recorder.Code)
		}
	})
	t.Run("header wins", func(t *testing.T) {
		verifier, handler, _ := newMiddlewareStack(t, MiddlewareOptions{SecretKey: testSecret})
		goldenLiveRecordInto(t, verifier)
		request := goldenIPRequest(http.MethodGet, "/api/submit?"+url.Values{TokenField: {"junk"}}.Encode(), nil)
		request.Header.Set(TokenHeader, token)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("the header must win over the query: %d", recorder.Code)
		}
	})
}

func TestMiddlewareScopePredicate(t *testing.T) {
	_, handler, calls := newMiddlewareStack(t, MiddlewareOptions{
		SecretKey:      testSecret,
		ScopePredicate: func(path string) bool { return strings.HasPrefix(path, "api/protected") },
	})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/public/feed", nil))
	if recorder.Code != http.StatusOK || *calls != 1 {
		t.Fatalf("an unprotected path must pass through untouched")
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/protected/pay", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("a protected path must demand a token: %d", recorder.Code)
	}
}

func TestMiddlewareDenialOverride(t *testing.T) {
	_, handler, _ := newMiddlewareStack(t, MiddlewareOptions{
		SecretKey: testSecret,
		Denied: func(w http.ResponseWriter, r *http.Request, decision VerifyDecision) {
			w.WriteHeader(http.StatusTeapot)
			_, _ = w.Write([]byte(decision.Error))
		},
	})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/submit", nil))
	if recorder.Code != http.StatusTeapot {
		t.Fatalf("the denial override must be honored: %d", recorder.Code)
	}
}

func TestMiddlewareClientIP(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/x", nil)
	request.RemoteAddr = "198.51.100.7:41234"
	if got := ClientIPFromRequest(request, false); got != "198.51.100.7" {
		t.Fatalf("the remote address is the default source: %s", got)
	}
	request.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	if got := ClientIPFromRequest(request, false); got != "198.51.100.7" {
		t.Fatalf("an untrusted proxy header is ignored: %s", got)
	}
	if got := ClientIPFromRequest(request, true); got != "203.0.113.9" {
		t.Fatalf("a trusted proxy header resolves the first hop: %s", got)
	}
}
