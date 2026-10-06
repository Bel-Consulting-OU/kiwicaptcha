package kiwicaptcha

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The sidecar-delegation test: the spawned kiwicaptcha-verifier (the
// full Rust core with the real execution verifier) fronts an
// execution-armed challenge; the SDK's fail-closed default refuses it,
// the sidecar policy delegates and accepts. The evidence helper mints
// the armed record and its browser-equivalent executed trace, writing
// the pending envelope into the sidecar's file store through the
// store's own code.

const repoRootForSidecar = "../.."

func buildSidecarBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(repoRootForSidecar, "target", "debug", "kiwicaptcha-verifier")
	if _, err := os.Stat(binary); err == nil {
		return binary
	}
	build := exec.Command("cargo", "build", "-q", "-p", "kiwicaptcha-verifier")
	build.Dir = repoRootForSidecar
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("the verifier crate did not build (cargo required): %v: %s", err, out)
	}
	return binary
}

func buildEvidenceHelper(t *testing.T) string {
	t.Helper()
	build := exec.Command("cargo", "build", "-q", "-p", "kiwicaptcha-verifier", "--features", "test-fixtures")
	build.Dir = repoRootForSidecar
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("the evidence helper did not build: %v: %s", err, out)
	}
	return filepath.Join(repoRootForSidecar, "target", "debug", "kiwicaptcha-verifier")
}

func freeLocalPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("no local port: %v", err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port
}

type sidecarProcess struct {
	cmd     *exec.Cmd
	baseURL string
	secret  string
	doc     struct {
		Record  json.RawMessage `json:"record"`
		Nonce   string          `json:"nonce"`
		Program string          `json:"program"`
		Trace   string          `json:"trace"`
		Digest  string          `json:"digest"`
	}
}

func spawnArmedSidecar(t *testing.T) *sidecarProcess {
	t.Helper()
	binary := buildSidecarBinary(t)
	helper := buildEvidenceHelper(t)
	storeDir := t.TempDir()
	secret := "sidecar-delegation-secret-0123456789abcdef"
	port := freeLocalPort(t)

	// The armed record + its browser-equivalent executed evidence,
	// minted by the core and persisted into the sidecar's own file
	// store by the store's own writer.
	out, err := exec.Command(helper, "exec-evidence",
		"--secret", secret, "--scope", "login", "--action", "login-action",
		"--version", "1", "--store-dir", storeDir).Output()
	if err != nil {
		t.Fatalf("the evidence helper failed: %v: %s", err, out)
	}
	process := &sidecarProcess{baseURL: fmt.Sprintf("http://127.0.0.1:%d", port), secret: secret}
	if err := json.Unmarshal(out, &process.doc); err != nil {
		t.Fatalf("the evidence document did not parse: %v", err)
	}

	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("KIWI_LISTEN=http://127.0.0.1:%d", port),
		"KIWI_SECRET="+secret,
		"KIWI_STORE=file="+storeDir,
		"KIWI_BINDING=none",
		"KIWI_PROFILE=sha16",
	)
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("the sidecar did not start: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(process.baseURL + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				process.cmd = cmd
				return process
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the sidecar never answered /healthz")
	return nil
}

func TestSidecarDelegationForExecutionArmedRecords(t *testing.T) {
	sidecar := spawnArmedSidecar(t)
	record, err := ParseChallengeRecord(sidecar.doc.Record)
	if err != nil {
		t.Fatalf("the armed record did not parse: %v", err)
	}
	if record.ExecutionProgram == "" {
		t.Fatal("the minted record must be execution-armed")
	}

	buildCase := func() (string, *Verifier) {
		storage := NewMemoryStorage()
		storeRecord(t, storage, record)
		verifier := newTestVerifier(t, VerifierConfig{}, time.Now().Unix())
		verifier.Storage = storage
		counter := solveSha(record.Prefix, record.Salt, int(record.TargetBits))
		token := CreateToken(record.Nonce, counter, 5000, NewJSONObject(), sidecar.doc.Digest, sidecar.doc.Trace, "").Encode()
		return token, verifier
	}

	// The fail-closed default: the armed record refuses exactly as
	// before the delegation plane existed.
	token, failClosed := buildCase()
	outcome := failClosed.Verify(token, VerifyOptions{SecretKey: sidecar.secret, ExpectedScope: "login"})
	if outcome.Valid || outcome.Error != ErrCodeExecutionMismatch {
		t.Fatalf("the fail-closed default must refuse the armed record: %+v", outcome)
	}

	// The sidecar policy: the same token verifies through the
	// delegation and the verdict merges into this SDK's outcome.
	tokenDelegated, delegated := buildCase()
	accepted := delegated.Verify(tokenDelegated, VerifyOptions{
		SecretKey:       sidecar.secret,
		ExpectedScope:   "login",
		ExecutionPolicy: &ExecutionPolicy{SidecarURL: sidecar.baseURL},
	})
	if !accepted.Valid {
		t.Fatalf("the sidecar delegation must accept the armed solve: code=%s detail=%s", accepted.Error, accepted.Detail)
	}

	// Single-use semantics: the sidecar consumed; a replay of the same
	// token is refused by the sidecar as a duplicate, never re-accepted.
	replay := delegated.Verify(tokenDelegated, VerifyOptions{
		SecretKey:       sidecar.secret,
		ExpectedScope:   "login",
		ExecutionPolicy: &ExecutionPolicy{SidecarURL: sidecar.baseURL},
	})
	if replay.Valid {
		t.Fatal("a delegated replay must never re-accept")
	}
	if replay.Error != ErrCodeAlreadyConsumed && replay.Error != ErrCodeRecordNotFound {
		t.Fatalf("the replay must answer the consumed vocabulary: %s", replay.Error)
	}

	// An unreachable sidecar fails closed with the retry disposition:
	// the capability is unavailable, the record stays intact.
	fresh, verifierDown := buildCase()
	down := verifierDown.Verify(fresh, VerifyOptions{
		SecretKey:       sidecar.secret,
		ExpectedScope:   "login",
		ExecutionPolicy: &ExecutionPolicy{SidecarURL: "http://127.0.0.1:1", TimeoutMs: 300},
	})
	if down.Valid || down.Error != ErrCodeStorageUnavailable {
		t.Fatalf("an unreachable sidecar must answer the retry disposition: %+v", down)
	}
}
func TestSidecarPolicyRequiresBearerWhenConfigured(t *testing.T) {
	// A bearer-rejecting sidecar (401) answers the deny vocabulary,
	// never a retry into an untrusted verifier.
	server := newUnauthedSidecarDouble(t)
	defer func() { server.Close() }()
	policy := &ExecutionPolicy{SidecarURL: server.URL, BearerToken: "wrong"}
	outcome := delegateExecutionVerify("tok", &ChallengeRecord{}, VerifyOptions{ExpectedScope: "login"}, policy)
	if outcome.Valid || outcome.Error != ErrCodeExecutionMismatch {
		t.Fatalf("a refused credential must deny: %+v", outcome)
	}
}

func TestSidecarSuccessCarriesNonceAndRequestBinding(t *testing.T) {
	// The delegated success is an ordinary fresh acceptance: the
	// decision handle must be the verified nonce and the record's
	// application-transaction binding must ride the outcome, never be
	// dropped or swapped with the nonce.
	server := newUnauthedSidecarDouble(t)
	defer func() { server.Close() }()
	policy := &ExecutionPolicy{SidecarURL: server.URL, BearerToken: "right"}
	record := &ChallengeRecord{
		Nonce:          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		RequestBinding: "checkout:order-42",
		DecoyField:     "website",
	}
	outcome := delegateExecutionVerify("tok", record, VerifyOptions{ExpectedScope: "login"}, policy)
	if !outcome.Valid {
		t.Fatalf("an accepted sidecar verdict must accept: %+v", outcome)
	}
	if outcome.Nonce != record.Nonce {
		t.Fatalf("the decision handle must be the verified nonce: got %q", outcome.Nonce)
	}
	if outcome.RequestBinding != record.RequestBinding {
		t.Fatalf("the record's request binding must ride the outcome: got %q", outcome.RequestBinding)
	}
	if outcome.DecoyField != record.DecoyField {
		t.Fatalf("the decoy field must ride the outcome: got %q", outcome.DecoyField)
	}
}

// newUnauthedSidecarDouble is a minimal 401 endpoint standing in for
// the bearer gate of the real sidecar's HTTP surface.
func newUnauthedSidecarDouble(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer right" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"error-codes":["invalid-input-response"]}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"kiwi-code":"ok"}`))
	})
	return httptest.NewServer(mux)
}

func TestSidecarDelegationForwardsExpectedRequestBinding(t *testing.T) {
	// The delegation body always carries the binding this SDK's
	// verification context expects, so the sidecar enforces the same
	// exact expectation instead of silently dropping it. An unenforced
	// context sends no expectation at all (the sidecar's documented
	// backward-compatible posture).
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = nil
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"success":true,"kiwi-code":"ok"}`))
	}))
	defer func() { server.Close() }()
	policy := &ExecutionPolicy{SidecarURL: server.URL}
	record := &ChallengeRecord{RequestBinding: "checkout:order-42"}

	// The default context is exact: the expected binding rides the body.
	outcome := delegateExecutionVerify("tok", record, VerifyOptions{
		SecretKey:              "s",
		ExpectedScope:          "login",
		ExpectedRequestBinding: "checkout:order-42",
	}, policy)
	if !outcome.Valid {
		t.Fatalf("the delegated verify must accept: %+v", outcome)
	}
	if got["expected_request_binding"] != "checkout:order-42" {
		t.Fatalf("the expected request binding must ride the body: %v", got)
	}

	// An empty expected binding asserts an explicitly unbound record.
	delegateExecutionVerify("tok", &ChallengeRecord{}, VerifyOptions{
		SecretKey:     "s",
		ExpectedScope: "login",
	}, policy)
	if got["expected_request_binding"] != "" {
		t.Fatalf("the empty expectation must assert unbound: %v", got)
	}

	// An explicitly unenforced context omits the field entirely.
	unenforced := UnenforcedBinding()
	delegateExecutionVerify("tok", record, VerifyOptions{
		SecretKey:          "s",
		ExpectedScope:      "login",
		BindingExpectation: &unenforced,
	}, policy)
	if _, present := got["expected_request_binding"]; present {
		t.Fatalf("an unenforced context must send no expectation: %v", got)
	}
}

func TestSidecarPolicyDescribe(t *testing.T) {
	if got := (*ExecutionPolicy)(nil).describeDelegation(); got != "fail-closed" {
		t.Fatalf("the nil policy is fail-closed: %s", got)
	}
	if got := (&ExecutionPolicy{SidecarURL: "http://x"}).describeDelegation(); !strings.HasPrefix(got, "sidecar ") {
		t.Fatalf("the sidecar policy describes its target: %s", got)
	}
}
