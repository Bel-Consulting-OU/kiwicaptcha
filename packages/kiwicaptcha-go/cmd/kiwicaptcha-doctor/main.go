// Command kiwicaptcha-doctor validates a kiwicaptcha Go deployment:
// the settings shape, the secret length, a full one-shot store
// roundtrip, the configured scopes and the proof budget of the
// configured profile.
//
//	kiwicaptcha-doctor --secret "32 bytes or more" --store memory:// \
//	    --scopes login,comment --profile standard
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	kiwi "kiwicaptcha/kiwicaptcha-go"
)

func main() {
	secret := flag.String("secret", "", "the hmac master secret (32 bytes or more)")
	storeURL := flag.String("store", "memory://", "the store url: memory:// or redis://host:port")
	scopesFlag := flag.String("scopes", "", "comma separated accepted scopes")
	profile := flag.String("profile", "standard", "the deployment's challenge profile")
	flag.Parse()

	var scopes []string
	for _, scope := range strings.Split(*scopesFlag, ",") {
		if scope != "" {
			scopes = append(scopes, scope)
		}
	}

	results, opened := kiwi.DoctorRun(*secret, *storeURL, scopes, *profile)
	if closer, ok := opened.(interface{ Close() error }); ok && opened != nil {
		defer closer.Close()
	}
	failed := false
	for _, result := range results {
		marker := "ok  "
		if !result.OK {
			marker = "FAIL"
			failed = true
		}
		fmt.Printf("%s %s: %s\n", marker, result.Name, result.Detail)
	}
	if failed {
		fmt.Println("doctor: the deployment needs attention")
		os.Exit(1)
	}
	fmt.Println("doctor: every check passed")
}
