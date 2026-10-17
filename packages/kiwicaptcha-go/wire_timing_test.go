package kiwicaptcha

import (
	"strings"
	"testing"
	"time"
)

// The constant-time comparison behind the signature and rsw checks,
// measured against an early-exit comparator that calibrates the noise
// floor. A position-dependent timing difference on the production
// comparator fails the test.

const (
	timingLength = 8192
	timingRounds = 25
	timingCalls  = 1000
)

var (
	timingSink bool
	timingA    string
	timingB    string
)

func measureComparator(f func(string, string) bool, a, b string) float64 {
	timingA, timingB = a, b
	best := float64(1 << 62)
	for round := 0; round < timingRounds; round++ {
		start := time.Now()
		for call := 0; call < timingCalls; call++ {
			timingSink = f(timingA, timingB)
		}
		elapsed := float64(time.Since(start).Nanoseconds()) / float64(timingCalls)
		if elapsed < best {
			best = elapsed
		}
	}
	return best
}

//go:noinline
func leakingComparator(a, b string) bool {
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestConstantTimeEqualsDoesNotLeakTheMismatchPosition(t *testing.T) {
	first := strings.Repeat("a", timingLength)
	head := "b" + first[1:]
	last := first[:timingLength-1] + "b"

	noiseA := measureComparator(leakingComparator, first, first)
	noiseB := measureComparator(leakingComparator, first, first)
	noise := noiseA - noiseB
	if noise < 0 {
		noise = -noise
	}
	if noise < 1 {
		noise = 1
	}

	leakFirst := measureComparator(leakingComparator, first, head)
	leakLast := measureComparator(leakingComparator, first, last)
	leakDelta := leakLast - leakFirst
	if leakDelta < 0 {
		leakDelta = -leakDelta
	}
	if leakDelta <= maxFloat(noise*10, 1_000) {
		t.Fatalf("the measurement must see an early exit: first=%fns last=%fns noise=%fns", leakFirst, leakLast, noise)
	}

	real := realComparator
	realFirst := measureComparator(real, first, head)
	realLast := measureComparator(real, first, last)
	realDelta := realLast - realFirst
	if realDelta < 0 {
		realDelta = -realDelta
	}
	budget := maxFloat(maxFloat(noise*10, realFirst*0.20), 2_000)
	if realDelta > budget {
		t.Fatalf("ConstantTimeEquals leaked the mismatch position: first=%fns last=%fns noise=%fns", realFirst, realLast, noise)
	}
}

//go:noinline
func realComparator(a, b string) bool { return ConstantTimeEquals(a, b) }

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
