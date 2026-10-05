package com.kiwicaptcha;

import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The four purpose keys derived from one master secret,
 * byte-identical with the php DerivedKeys. Every purpose derives its
 * own key, so a compromise in one purpose never leaks the others. The
 * construction is the RFC 5869 extract and expand step over sha256:
 *
 * prk = hmac-sha256(salt, master)
 * k_x = hmac-sha256(prk, info + 0x01)
 */
public final class DerivedKeys {
    /** The challenge signing purpose key. */
    public final byte[] challengeKey;
    /** The ip binding purpose key. */
    public final byte[] ipBindKey;
    /** The result token purpose key. */
    public final byte[] resultKey;
    /** The server state mac purpose key. */
    public final byte[] serverStateKey;

    private DerivedKeys(byte[] challengeKey, byte[] ipBindKey, byte[] resultKey, byte[] serverStateKey) {
        this.challengeKey = challengeKey;
        this.ipBindKey = ipBindKey;
        this.resultKey = resultKey;
        this.serverStateKey = serverStateKey;
    }

    private static final Map<String, DerivedKeys> CACHE = new ConcurrentHashMap<>();

    /**
     * Derives the purpose keys for one master secret, memoized per
     * distinct master and tenant pair. A tenant id scopes the keys
     * under the per-tenant root, so tenants sharing a master secret
     * cannot forge each other's challenges or binding tags.
     */
    public static DerivedKeys fromMaster(String master, String tenantId) {
        if (master.getBytes(StandardCharsets.UTF_8).length < Kiwi.MIN_SECRET_BYTES) {
            throw new Canonical.SecretTooShortException();
        }
        String cacheKey = "0\u0000" + master;
        byte[] salt = Kiwi.HKDF_DEPLOY_SALT.getBytes(StandardCharsets.UTF_8);
        String material = master;
        if (tenantId != null && !tenantId.isEmpty()) {
            byte[] root = hkdfSha256(master.getBytes(StandardCharsets.UTF_8),
                    (Kiwi.INFO_TENANT_ROOT_PREFIX + tenantId).getBytes(StandardCharsets.UTF_8), salt, 32);
            cacheKey = "1\u0000" + tenantId + "\u0000" + master;
            salt = new byte[0];
            material = new String(root, StandardCharsets.ISO_8859_1);
        }
        DerivedKeys cached = CACHE.get(cacheKey);
        if (cached != null) {
            return cached;
        }
        byte[] materialBytes = material.getBytes(StandardCharsets.ISO_8859_1);
        DerivedKeys derived = new DerivedKeys(
                hkdfSha256(materialBytes, Kiwi.INFO_CHALLENGE_SIGN.getBytes(StandardCharsets.UTF_8), salt, 32),
                hkdfSha256(materialBytes, Kiwi.INFO_IP_BIND.getBytes(StandardCharsets.UTF_8), salt, 32),
                hkdfSha256(materialBytes, Kiwi.INFO_RESULT_TOKEN.getBytes(StandardCharsets.UTF_8), salt, 32),
                hkdfSha256(materialBytes, Kiwi.INFO_SERVER_STATE.getBytes(StandardCharsets.UTF_8), salt, 32));
        if (CACHE.size() >= 64) {
            CACHE.clear();
        }
        CACHE.put(cacheKey, derived);
        return derived;
    }

    /** One extract and expand step of RFC 5869 with sha256. */
    public static byte[] hkdfSha256(byte[] ikm, byte[] info, byte[] salt, int length) {
        byte[] effectiveSalt = salt.length == 0 ? new byte[32] : salt;
        Mac prkMac = Canonical.hmac(effectiveSalt);
        byte[] prk = prkMac.doFinal(ikm);
        byte[] out = new byte[length];
        byte[] t = new byte[0];
        int produced = 0;
        int counter = 1;
        while (produced < length) {
            Mac mac = Canonical.hmac(prk);
            mac.update(t);
            mac.update(info);
            mac.update((byte) counter);
            t = mac.doFinal();
            int take = Math.min(t.length, length - produced);
            System.arraycopy(t, 0, out, produced, take);
            produced += take;
            counter++;
        }
        return out;
    }
}
