package kiwicaptcha

import (
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/argon2"
)

// The RFC 9106 section 5.3 Argon2id input set exercises the general
// parameter space (four lanes), while the protocol profile always
// derives with one lane. x/crypto carries no secret or associated-data
// adder, so the RFC inputs are pinned through the reference-build
// differential tags below: the same table the pure implementations of
// the other SDKs answer, captured once from the C reference build.
var argon2DifferentialCases = map[[3]int]string{
	{1, 32, 3}:  "929ea45c6d883a86f284950fd0ed67f72aa687dd6ea22d25b6f833da6d50cf19",
	{1, 64, 3}:  "381612cb120864032b674082eb0144f821e9395f3f1ca74ab41ce8bd8e328921",
	{1, 128, 4}: "7661f1eaee47643ec423cb7018a29aaea546e985e256aec5c88cc68df75fdfdf",
	{1, 256, 1}: "a0e96c4b5be13e4c1ca75c71b8f0b54a26aa850a014315c405bf4212cae86d95",
	{2, 32, 3}:  "017d5cb68c17c85940a49908a52904e248311a0a0d56ad6827723ad5df24ad3d",
	{2, 64, 3}:  "61c1d3de8b09b930ef0eff624ebb407932ee6d65e4052e591ec79ab57d5397f8",
	{2, 128, 4}: "c1cfa0d681bfcbf022043e6cf948bab58868c5c812ed7b8920930d0ba537b772",
	{2, 256, 1}: "e88b33a5663804b559aa1ca5ec3e4d96ad0cf597165e2d1347dc9dfacc205d9d",
	{3, 32, 3}:  "4b8b04eb139f69296d99c24561a308708d01b0c7064914fb07a393474b90b388",
	{3, 64, 3}:  "3f161325d41c548325c608d8c67ceffcdeac5c88b76b177889ffeabbc6d3f125",
	{3, 128, 4}: "a3f01f43ea51ef167e713ab4f31a35adb292a1cc1ef3f73809f69e4e1eb094be",
	{3, 256, 1}: "29d826fb3ea732186a3e5ff2e705ae74d7d1ee646bba7d806280f1dbf5b104b3",
	{4, 32, 3}:  "13aecf7f9d2496db6382d49ab841c0cee84b5fab6d36c294b4c02bb578368eca",
	{4, 64, 3}:  "28c6c3d4239d0885247fc323c105388825304afa8b14573b42a0fdb428cee98c",
	{4, 128, 4}: "827d662123b4142d9b3c918ce78cfaf5141256ff14f907223e64956a42618160",
	{4, 256, 1}: "e3e8fb83637bba3475a41d3c8dda7f6c007d92deefef4a20c7dcc588a604d39e",
}

// risingSalt is the sixteen rising bytes of the shared fixture salt.
func risingSalt() []byte {
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}
	return salt
}

// TestArgon2idDifferentialVectors pins the native x/crypto derivation
// byte-exactly against the reference-build tags over the RFC 9106
// input space: one to four lanes, one to four passes, the memory
// rungs of the shared fixture table.
func TestArgon2idDifferentialVectors(t *testing.T) {
	for params, want := range argon2DifferentialCases {
		lanes, mCost, tCost := params[0], params[1], params[2]
		got := argon2.IDKey([]byte("prefix21"), risingSalt(), uint32(tCost), uint32(mCost), uint8(lanes), 32)
		if hex.EncodeToString(got) != want {
			t.Fatalf("lanes=%d m=%d t=%d: tag %s, want %s", lanes, mCost, tCost, hex.EncodeToString(got), want)
		}
	}
}

// TestArgon2idSodiumProtocolVector pins the exact libsodium tag the
// PHP verifier's sodium_crypto_pwhash produces for the protocol
// fixture profile (m_kib=64, t=3, p=1, a 32-byte tag).
func TestArgon2idSodiumProtocolVector(t *testing.T) {
	got := argon2.IDKey([]byte("prefix21"), risingSalt(), 3, 64, 1, 32)
	if hex.EncodeToString(got) != "381612cb120864032b674082eb0144f821e9395f3f1ca74ab41ce8bd8e328921" {
		t.Fatalf("protocol profile tag drifted: %s", hex.EncodeToString(got))
	}
}
