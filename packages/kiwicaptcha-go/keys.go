package kiwicaptcha

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"sync"
)

// DerivedKeys carries the four purpose keys derived from one master
// secret, byte-identical with the php DerivedKeys. Every purpose
// derives its own key, so a compromise in one purpose never leaks the
// others. The construction is the RFC 5869 extract and expand step
// over sha256:
//
//	prk = hmac-sha256(salt, master)
//	k_x = hmac-sha256(prk, info + 0x01)
type DerivedKeys struct {
	ChallengeKey   []byte
	IPBindKey      []byte
	ResultKey      []byte
	ServerStateKey []byte
}

var (
	derivedKeysCacheMu sync.Mutex
	derivedKeysCache   = map[string]*DerivedKeys{}
)

// ErrSecretTooShort is raised when a master secret is below the
// 32-byte entropy floor.
var ErrSecretTooShort = errors.New("kiwicaptcha: the master secret must be at least 32 bytes")

// hkdfSha256 runs one extract and expand step of RFC 5869 with sha256.
func hkdfSha256(ikm, info, salt []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	prk := mac.Sum(nil)
	out := make([]byte, 0, length+sha256.Size)
	var t []byte
	for counter := byte(1); len(out) < length; counter++ {
		mac = hmac.New(sha256.New, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

// DerivedKeysFromMaster derives the purpose keys for one master
// secret, memoized per distinct master and tenant pair. A tenant id
// scopes the keys under the per-tenant root, so tenants sharing a
// master secret cannot forge each other's challenges or binding tags.
func DerivedKeysFromMaster(master string, tenantID string) (*DerivedKeys, error) {
	if len(master) < MinSecretBytes {
		return nil, ErrSecretTooShort
	}
	cacheKey := "0\x00" + master
	salt := []byte(HkdfDeploySalt)
	if tenantID != "" {
		root := hkdfSha256([]byte(master), []byte(InfoTenantRootPrefix+tenantID), salt, 32)
		cacheKey = "1\x00" + tenantID + "\x00" + master
		salt = nil
		master = string(root)
	}
	derivedKeysCacheMu.Lock()
	if cached, ok := derivedKeysCache[cacheKey]; ok {
		derivedKeysCacheMu.Unlock()
		return cached, nil
	}
	derivedKeysCacheMu.Unlock()
	material := []byte(master)
	derived := &DerivedKeys{
		ChallengeKey:   hkdfSha256(material, []byte(InfoChallengeSign), salt, 32),
		IPBindKey:      hkdfSha256(material, []byte(InfoIPBind), salt, 32),
		ResultKey:      hkdfSha256(material, []byte(InfoResultToken), salt, 32),
		ServerStateKey: hkdfSha256(material, []byte(InfoServerState), salt, 32),
	}
	derivedKeysCacheMu.Lock()
	if len(derivedKeysCache) >= 64 {
		derivedKeysCache = map[string]*DerivedKeys{}
	}
	derivedKeysCache[cacheKey] = derived
	derivedKeysCacheMu.Unlock()
	return derived, nil
}
