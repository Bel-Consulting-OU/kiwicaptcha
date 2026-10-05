// Package kiwicaptcha is the Go server SDK for the KiwiCaptcha
// proof-of-work captcha. It verifies client-submitted solution tokens
// byte-for-byte compatible with the php, Rust and JavaScript cores.
//
// Verification is pure-local: the signature check, the message
// authentication codes and the caller's store adapter are the only
// inputs, and no call ever reaches a network service.
//
// The wire surface is pinned by the shared protocol corpus. This file
// mirrors the php constants in packages/kiwicaptcha-php, so every
// implementation accepts exactly the same record language.
package kiwicaptcha

// MaxShaTargetBits is the hard ceiling for issued sha256 difficulty.
const MaxShaTargetBits = 20

// MinSecretBytes is the minimum master secret length in bytes.
const MinSecretBytes = 32

// MinExecutionKeyBytes is the minimum execution key length in bytes.
const MinExecutionKeyBytes = 32

// MaxArgon2TargetBits is the ceiling for issued argon2id difficulty.
const MaxArgon2TargetBits = 10

// MinDifficulty is the absolute stored-record difficulty floor.
const MinDifficulty = 1

// MaxDifficulty is the absolute stored-record difficulty ceiling.
const MaxDifficulty = 20

// MaxTtlSecs is the hard ceiling for a stored record lifetime in
// seconds. Anything beyond it cannot come from a KiwiCaptcha issuer.
const MaxTtlSecs = 300

// MinRswT is the floor for the rsw sequential squaring count.
const MinRswT = 10_000

// MaxRswT is the ceiling for the rsw sequential squaring count.
const MaxRswT = 300_000

// RswTargetBitsPin is the canonical target_bits pin carried by an rsw
// record. The time-lock has no leading-zero target.
const RswTargetBitsPin = 1

// MaxStringBytes is the maximum wire string length of any record
// field, mirroring the serde parse ceiling.
const MaxStringBytes = 4096

// Protocol versions of the challenge canonical.
const (
	// BaseProtocolVersion is the identityless, decoyless,
	// executionless canonical version.
	BaseProtocolVersion = 2
	// DecoyProtocolVersion is the decoy-capable canonical version.
	DecoyProtocolVersion = 3
	// ExecutionProtocolVersion is the execution-capable canonical
	// version.
	ExecutionProtocolVersion = 4
	// RswIdentityProtocolVersion is the identity-bearing rsw canonical
	// version. Identity-bearing records at versions 2 through 4 are
	// the pre-v5 legacy shape, accepted only for a bounded migration
	// window.
	RswIdentityProtocolVersion = 5
	// MaxProtocolVersion is the maximum accepted protocol version.
	MaxProtocolVersion = 5
)

// MaxExecutionVersion is the execution-dimension grammar ceiling.
const MaxExecutionVersion = 5

// MaxClockSkew is the maximum tolerated future issuance skew in
// seconds. A challenge claiming issuance further ahead than this is
// rejected as expired.
const MaxClockSkew = 60

// SkewToleranceUs is the host clock skew tolerance for the minimum
// duration check, in microseconds.
const SkewToleranceUs = 5_000_000

// Verifier process ceilings for argon2id, applied after signature
// authentication and before any allocation.
const (
	MinArgonMemoryKib = 8
	MaxArgonMemoryKib = 65_536
	MinArgonTime      = 3
	MaxArgonTime      = 16
	MinParallelism    = 1
	MaxParallelism    = 4
)

// MaxSolverCounter is the solver search ceiling shared with the widget
// and the wasm core.
const MaxSolverCounter = 20_000_000

// MaxDurationMs is the hard ceiling for the client reported token
// duration.
const MaxDurationMs = 3_600_000

// NonceB64Bytes is the decoded nonce length in bytes.
const NonceB64Bytes = 32

// SaltB64Bytes is the decoded record salt length in bytes.
const SaltB64Bytes = 16

// Key derivation labels, byte-identical with the php DerivedKeys.
const (
	HkdfDeploySalt       = "kiwicaptcha/deploy-salt/v1"
	InfoChallengeSign    = "kiwi/v2/challenge-sign"
	InfoIPBind           = "kiwi/v2/ip-bind"
	InfoResultToken      = "kiwi/v2/result-token"
	InfoServerState      = "kiwi/v2/server-state"
	InfoTenantRootPrefix = "kiwi/v2/tenant/"
	RecordMetaDomain     = "kiwi/record-meta/v1"
	ConsumedResultDomain = "kiwi/consumed-result/v1"
	IPBindDomain         = "kiwicaptcha/ip-bind/v2"
	MaxRecordIdentityB64 = 512
)
