package chi

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	kiwi "kiwicaptcha/kiwicaptcha-go"
)

const testSecret = "0123456789abcdef0123456789abcdef"

const goldenIssuedAt = 1_900_000_000

func newVerifier(t *testing.T) *kiwi.Verifier {
	t.Helper()
	config, err := kiwi.NewVerifierConfig(kiwi.VerifierConfig{
		NowFunc: func() time.Time { return time.Unix(goldenIssuedAt, 0) },
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	storage, err := kiwi.OpenStore("memory://")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	verifier, err := kiwi.NewVerifier(storage, config)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	return verifier
}

func goldenRecordInto(t *testing.T, verifier *kiwi.Verifier) *kiwi.ChallengeRecord {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "golden_sha256_v2.json"))
	if err != nil {
		t.Fatalf("golden record: %v", err)
	}
	var document struct {
		Record json.RawMessage `json:"record"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("golden record: %v", err)
	}
	record, err := kiwi.ParseChallengeRecord(document.Record)
	if err != nil {
		t.Fatalf("golden record: %v", err)
	}
	storer, ok := verifier.Storage.(interface {
		StoreRecord(*kiwi.ChallengeRecord) error
	})
	if !ok {
		t.Fatalf("the store cannot accept records")
	}
	if err := storer.StoreRecord(record); err != nil {
		t.Fatalf("store: %v", err)
	}
	return record
}

func goldenToken(t *testing.T, record *kiwi.ChallengeRecord) string {
	t.Helper()
	saltBytes, err := base64.StdEncoding.DecodeString(record.Salt)
	if err != nil {
		t.Fatalf("salt: %v", err)
	}
	counter := 0
	for {
		digest := sha256.Sum256([]byte(record.Prefix + strconv.Itoa(counter) + string(saltBytes)))
		if kiwi.LeadingZeroBits(digest[:]) >= record.TargetBits {
			break
		}
		counter++
	}
	return kiwi.CreateToken(record.Nonce, counter, 5000, kiwi.NewJSONObject(), "", "", "").Encode()
}
