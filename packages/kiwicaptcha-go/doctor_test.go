package kiwicaptcha

import (
	"strings"
	"testing"
)

func TestDoctorRunAllChecksPass(t *testing.T) {
	results, store := DoctorRun(strings.Repeat("s", 32), "memory://", []string{"login", "comment"}, "standard")
	if closer, ok := store.(interface{ Close() error }); ok {
		defer closer.Close()
	}
	names := []string{}
	for _, result := range results {
		names = append(names, result.Name)
		if !result.OK {
			t.Fatalf("%s failed: %s", result.Name, result.Detail)
		}
	}
	if strings.Join(names, ",") != "settings,store,scopes,proof_budget" {
		t.Fatalf("the check order drift: %v", names)
	}
}

func TestDoctorFailsShortSecretAndBadProfile(t *testing.T) {
	result := DoctorCheckSettings("short", "standard")
	if result.OK {
		t.Fatalf("a short secret must fail")
	}
	result = DoctorCheckSettings(strings.Repeat("s", 32), "nonsense")
	if result.OK {
		t.Fatalf("an unknown profile must fail")
	}
}

func TestDoctorFailsBadScopeAndStore(t *testing.T) {
	result := DoctorCheckScopes([]string{"bad scope"})
	if result.OK {
		t.Fatalf("a scope outside the identifier alphabet must fail")
	}
	_, store, _ := DoctorCheckStore("gopher://nope")
	if store != nil {
		t.Fatalf("a refused url opens no store")
	}
	// The redis url refuses without a reachable server, fail closed.
	if _, store, _ := DoctorCheckStore("redis://127.0.0.1:1"); store != nil {
		t.Fatalf("an unreachable redis opens no store")
	}
}

func TestDoctorProofBudgetReportsRungs(t *testing.T) {
	for _, profile := range Profiles {
		result := DoctorCheckProofBudget(profile)
		if !result.OK {
			t.Fatalf("%s: %s", profile, result.Detail)
		}
	}
	if result := DoctorCheckProofBudget("nonsense"); result.OK {
		t.Fatalf("an unknown profile must fail")
	}
}
