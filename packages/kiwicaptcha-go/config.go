package kiwicaptcha

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

// BuildVerifier wires the settings into a Verifier over the store
// adapter chosen by the store url.
func (s Settings) BuildVerifier() (*Verifier, error) {
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
