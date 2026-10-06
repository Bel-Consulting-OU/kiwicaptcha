package kiwicaptcha

import (
	"errors"
	"fmt"
)

// Deployment settings: the four-setting quickstart and the verifier
// factory. Settings carries the deployment inputs the SDK needs at
// boot: the signing Secret, the Store url, the accepted Scopes and the
// Profile naming the challenge budget the deployment issues.
// Everything else stays optional.

// The named challenge budgets, mirroring the issuance-side profiles:
// the sha256 standard rung and the three argon2id memory rungs.
var Profiles = []string{"standard", "argon16", "argon32", "argon64"}

// Settings is the four-setting quickstart plus the optional
// expectation knobs.
type Settings struct {
	// Secret is the hmac master secret, at least 32 bytes.
	Secret string
	// Store is a store url: memory:// (the default) or redis://host.
	Store string
	// Scopes lists the accepted challenge scopes; an empty list
	// accepts any scope.
	Scopes []string
	// Profile names the deployment's issuance budget for the doctor's
	// report: standard, argon16, argon32 or argon64.
	Profile string
	// Region pins the expected deployment region when set.
	Region string
	// ExpectedPolicyVersion pins the security-policy epoch when set;
	// PolicyVersionFloor declares the rollout window below it.
	ExpectedPolicyVersion int
	PolicyVersionFloor    int
	// ExpectedIssuer pins the deployment issuer when set.
	ExpectedIssuer string
	// TenantID scopes the derived purpose keys when set.
	TenantID string
	// AcceptLegacyV1 opens the bounded v1 migration window.
	AcceptLegacyV1 bool
}

// ProfileKnown reports whether the profile names a shipped budget.
func ProfileKnown(profile string) bool {
	for _, candidate := range Profiles {
		if candidate == profile {
			return true
		}
	}
	return false
}

// ProfileArgonParams maps each argon profile to the signed rung it
// issues: memory in KiB, time cost and parallelism.
var ProfileArgonParams = map[string][3]int{
	"argon16": {16 * 1024, 3, 1},
	"argon32": {32 * 1024, 3, 1},
	"argon64": {64 * 1024, 3, 1},
}

// RungVerifiable reports whether this verifier runtime can recompute
// the argon2id rung: inside the process ceilings and the protocol
// derivation profile (p == 1, t at least 3).
func RungVerifiable(mKib, t, p int) bool {
	return mKib >= MinArgonMemoryKib && mKib <= MaxArgonMemoryKib &&
		t >= MinArgonTime && t <= MaxArgonTime &&
		p == 1
}

// BuildVerifier wires the settings into a Verifier over the store
// adapter chosen by the store url. The issuer guard runs here: a
// profile naming a rung this verifier cannot verify is a loud
// configuration error, never a silent downgrade.
func (s Settings) BuildVerifier() (*Verifier, error) {
	if !ProfileKnown(s.Profile) {
		return nil, errors.New("kiwicaptcha: the profile must be one of standard, argon16, argon32, argon64")
	}
	if rung, ok := ProfileArgonParams[s.Profile]; ok && !RungVerifiable(rung[0], rung[1], rung[2]) {
		return nil, fmt.Errorf(
			"kiwicaptcha: profile %s issues an argon2id rung (m_kib=%d t=%d p=%d) this verifier cannot verify — refusing to issue it (never silently downgraded)",
			s.Profile, rung[0], rung[1], rung[2])
	}
	config, err := NewVerifierConfig(VerifierConfig{
		AcceptLegacyV1:        s.AcceptLegacyV1,
		Region:                s.Region,
		ExpectedPolicyVersion: s.ExpectedPolicyVersion,
		PolicyVersionFloor:    s.PolicyVersionFloor,
		ExpectedIssuer:        s.ExpectedIssuer,
		TenantID:              s.TenantID,
	})
	if err != nil {
		return nil, err
	}
	storage, err := OpenStore(s.Store)
	if err != nil {
		return nil, err
	}
	return NewVerifier(storage, config)
}
