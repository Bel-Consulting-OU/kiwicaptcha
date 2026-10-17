package kiwicaptcha

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newMiddlewareStack(t *testing.T, expectedScope string, options MiddlewareOptions) (*Verifier, http.Handler, *int) {
	t.Helper()
	verifier := newTestVerifier(t, VerifierConfig{}, goldenIssuedAt)
	calls := 0
	handler := Middleware(verifier, expectedScope, options)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	handler := Middleware(verifier, "login", MiddlewareOptions{
		SecretKey: testSecret,
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
	_, handler, calls := newMiddlewareStack(t, "login", MiddlewareOptions{SecretKey: testSecret})
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
	verifier, handler, calls := newMiddlewareStack(t, "login", MiddlewareOptions{SecretKey: testSecret})
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
	handler := Middleware(verifier, "login", MiddlewareOptions{
		SecretKey: testSecret,
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
		verifier, handler, calls := newMiddlewareStack(t, "login", MiddlewareOptions{SecretKey: testSecret})
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
		verifier, handler, calls := newMiddlewareStack(t, "login", MiddlewareOptions{SecretKey: testSecret})
		goldenLiveRecordInto(t, verifier)
		request := goldenIPRequest(http.MethodGet, "/api/submit?"+url.Values{TokenField: {token}}.Encode(), nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK || *calls != 1 {
			t.Fatalf("the query source must work: %d", recorder.Code)
		}
	})
	t.Run("header and query conflict", func(t *testing.T) {
		verifier, handler, calls := newMiddlewareStack(t, "login", MiddlewareOptions{SecretKey: testSecret})
		goldenLiveRecordInto(t, verifier)
		request := goldenIPRequest(http.MethodGet, "/api/submit?"+url.Values{TokenField: {"junk"}}.Encode(), nil)
		request.Header.Set(TokenHeader, token)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden || *calls != 0 {
			t.Fatalf("distinct header and query tokens must refuse: %d calls=%d", recorder.Code, *calls)
		}
		if !strings.Contains(recorder.Body.String(), `"error":"token_source_conflict"`) {
			t.Fatalf("the conflict must carry its typed code: %s", recorder.Body.String())
		}
	})
}

func TestMiddlewareTokenAuthorityMatrix(t *testing.T) {
	rows := []struct {
		name   string
		header []string
		form   []string
		query  []string
		status int
		code   string
	}{
		{"header only", []string{"TOKEN"}, nil, nil, http.StatusOK, ""},
		{"form only", nil, []string{"TOKEN"}, nil, http.StatusOK, ""},
		{"query only", nil, nil, []string{"TOKEN"}, http.StatusOK, ""},
		{"header A form B", []string{"TOKEN"}, []string{"other"}, nil, http.StatusForbidden, "token_source_conflict"},
		{"header A query B", []string{"TOKEN"}, nil, []string{"other"}, http.StatusForbidden, "token_source_conflict"},
		{"form A query B", nil, []string{"TOKEN"}, []string{"other"}, http.StatusForbidden, "token_source_conflict"},
		{"two header values", []string{"TOKEN", "other"}, nil, nil, http.StatusForbidden, "token_source_conflict"},
		{"repeated form values", nil, []string{"TOKEN", "other"}, nil, http.StatusForbidden, "token_source_conflict"},
		{"repeated query values", nil, nil, []string{"TOKEN", "other"}, http.StatusForbidden, "token_source_conflict"},
		{"same token every source", []string{"TOKEN"}, []string{"TOKEN"}, []string{"TOKEN"}, http.StatusOK, ""},
		{"same repeated form values", nil, []string{"TOKEN", "TOKEN"}, nil, http.StatusOK, ""},
		{"same repeated query values", nil, nil, []string{"TOKEN", "TOKEN"}, http.StatusOK, ""},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			verifier, handler, calls := newMiddlewareStack(t, "login", MiddlewareOptions{SecretKey: testSecret})
			goldenLiveRecordInto(t, verifier)
			live := goldenLiveToken(t)
			material := func(values []string) []string {
				out := make([]string, 0, len(values))
				for _, value := range values {
					if value == "TOKEN" {
						value = live
					}
					out = append(out, value)
				}
				return out
			}
			target := "/api/submit"
			query := url.Values{}
			for _, value := range material(row.query) {
				query.Add(TokenField, value)
			}
			if len(query) > 0 {
				target += "?" + query.Encode()
			}
			body := url.Values{}
			for _, value := range material(row.form) {
				body.Add(TokenField, value)
			}
			var reader io.Reader
			if len(body) > 0 {
				reader = strings.NewReader(body.Encode())
			}
			request := goldenIPRequest(http.MethodPost, target, reader)
			if len(body) > 0 {
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			for _, value := range material(row.header) {
				request.Header.Add(TokenHeader, value)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != row.status {
				t.Fatalf("status %d, want %d: %s", recorder.Code, row.status, recorder.Body.String())
			}
			if row.code != "" && !strings.Contains(recorder.Body.String(), `"error":"`+row.code+`"`) {
				t.Fatalf("missing code %s: %s", row.code, recorder.Body.String())
			}
			if row.status == http.StatusOK && *calls != 1 {
				t.Fatalf("an agreed token must verify once: calls=%d", *calls)
			}
			if row.status != http.StatusOK && *calls != 0 {
				t.Fatalf("a refused request must never reach the verifier: calls=%d", *calls)
			}
		})
	}
}

func TestMiddlewareScopePredicate(t *testing.T) {
	_, handler, calls := newMiddlewareStack(t, "login", MiddlewareOptions{
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
	_, handler, _ := newMiddlewareStack(t, "login", MiddlewareOptions{
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
	if got := ClientIPFromRequest(request, nil); got != "198.51.100.7" {
		t.Fatalf("the remote address is the default source: %s", got)
	}
	request.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	if got := ClientIPFromRequest(request, nil); got != "198.51.100.7" {
		t.Fatalf("an untrusted proxy header is ignored: %s", got)
	}
	// The peer itself must sit inside the trust list before any
	// forwarded header is read at all.
	if got := ClientIPFromRequest(request, []string{"10.0.0.0/24"}); got != "198.51.100.7" {
		t.Fatalf("a header from an untrusted peer is ignored: %s", got)
	}
	request.RemoteAddr = "10.0.0.9:41234"
	if got := ClientIPFromRequest(request, []string{"10.0.0.0/24"}); got != "203.0.113.9" {
		t.Fatalf("a trusted peer unlocks the forwarded walk: %s", got)
	}
}
