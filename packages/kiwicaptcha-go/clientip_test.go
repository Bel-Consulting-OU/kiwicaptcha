package kiwicaptcha

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// The shared client-IP test vectors, asserted against the Go
// resolver. Every SDK runs the same scenarios from
// tools/client-ip/test-vectors.json, so one request resolves to one
// canonical IP everywhere.
type vectorFile struct {
	CidrCases []struct {
		Cidr    string `json:"cidr"`
		IP      string `json:"ip"`
		Matches bool   `json:"matches"`
	} `json:"cidr_cases"`
	Scenarios []struct {
		ID            string   `json:"id"`
		Peer          string   `json:"peer"`
		XffLines      []string `json:"xff_lines"`
		RealIP        *string  `json:"real_ip"`
		Trusted       []string `json:"trusted"`
		Expected      string   `json:"expected"`
		ExpectedMerge *string  `json:"expected_merged"`
	} `json:"scenarios"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tools", "client-ip", "test-vectors.json"))
	if err != nil {
		t.Fatalf("read shared vectors: %v", err)
	}
	var vectors vectorFile
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse shared vectors: %v", err)
	}
	return vectors
}

func TestSharedCidrCases(t *testing.T) {
	vectors := loadVectors(t)
	for _, tc := range vectors.CidrCases {
		prefixes := trustedPrefixes([]string{tc.Cidr})
		addr, err := netip.ParseAddr(tc.IP)
		matched := err == nil && ipInTrusted(addr, prefixes)
		if matched != tc.Matches {
			t.Fatalf("cidr %s vs %s: got %v, want %v", tc.Cidr, tc.IP, matched, tc.Matches)
		}
	}
}

func TestSharedScenarios(t *testing.T) {
	vectors := loadVectors(t)
	for _, sc := range vectors.Scenarios {
		request, err := http.NewRequest(http.MethodPost, "/x", nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		request.RemoteAddr = sc.Peer
		// The net/http surface sees every header line, so a repeated
		// header is visible and must fail closed.
		for _, line := range sc.XffLines {
			request.Header.Add("X-Forwarded-For", line)
		}
		if sc.RealIP != nil {
			request.Header.Set("X-Real-IP", *sc.RealIP)
		}
		got := ClientIPFromRequest(request, sc.Trusted)
		if got != sc.Expected {
			t.Fatalf("scenario %s: got %q, want %q", sc.ID, got, sc.Expected)
		}
	}
}

func TestCanonicalIPEdges(t *testing.T) {
	cases := map[string]string{
		"192.0.2.10":            "192.0.2.10",
		" 192.0.2.10:4711 ":     "192.0.2.10",
		"[2001:DB8::1]":         "2001:db8::1",
		"[2001:db8::1]:4711":    "2001:db8::1",
		"::ffff:198.51.100.5":   "198.51.100.5",
		"2001:0db8:0:0:0:0:0:1": "2001:db8::1",
	}
	for input, want := range cases {
		if got := canonicalIP(input); got != want {
			t.Fatalf("canonicalIP(%q) = %q, want %q", input, got, want)
		}
	}
	rejected := []string{
		"", "unknown", "_obfuscated", "[2001:db8::1]:notaport",
		"[2001:db8::1]garbage", "1.2.3.4:0", "0:1.2.3.4", "1.2.3.4.5",
		"3232235521", "01.2.3.4", "fe80::1%eth0",
	}
	for _, input := range rejected {
		if got := canonicalIP(input); got != "" {
			t.Fatalf("canonicalIP(%q) = %q, want empty", input, got)
		}
	}
}
