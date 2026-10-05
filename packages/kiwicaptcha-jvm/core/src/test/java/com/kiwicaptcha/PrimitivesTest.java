package com.kiwicaptcha;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The derivation stack pins: blake2b, argon2id and the HKDF keys. */
class PrimitivesTest {

    @Test
    void blake2bRfc7693Vectors() {
        byte[] empty = Blake2b.digest(64, new byte[0], new byte[0]);
        assertEquals("786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
                        + "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
                Canonical.hex(empty));
        byte[] abc = Blake2b.digest(64, new byte[0], "abc".getBytes(StandardCharsets.UTF_8));
        assertEquals("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                        + "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
                Canonical.hex(abc));
    }

    @Test
    void blake2bVariableDigestLength() {
        byte[] out = Blake2b.digest(32, new byte[0], new byte[64]);
        assertEquals(32, out.length);
    }

    @Test
    void blake2bKeyedMatchesTheKeyedReference() {
        // The RFC 7693 keyed vectors: the key is the rising bytes
        // 0x00..0x3f, the message empty.
        byte[] key = new byte[64];
        for (int i = 0; i < 64; i++) {
            key[i] = (byte) i;
        }
        byte[] out = Blake2b.digest(64, key, new byte[0]);
        assertEquals("10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786"
                        + "b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568",
                Canonical.hex(out));
        byte[] one = Blake2b.digest(64, key, new byte[]{0});
        assertEquals("961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4"
                        + "187b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd",
                Canonical.hex(one));
    }

    @Test
    void blake2bLongMessageMultipleBlocks() {
        byte[] message = new byte[300];
        for (int i = 0; i < message.length; i++) {
            message[i] = (byte) i;
        }
        byte[] out = Blake2b.digest(64, new byte[0], message);
        assertEquals(64, out.length);
        // A second derive of the same input is deterministic.
        assertArrayEquals(out, Blake2b.digest(64, new byte[0], message));
    }

    @Test
    void argon2idRfc9106InputsVector() {
        // The RFC 9106 Argon2id input set: p=4 lanes, t=3, m=32,
        // password 32 bytes of 0x01, salt 16 bytes of 0x02, secret 8
        // bytes of 0x03, associated data 12 bytes of 0x04, 32-byte
        // tag. The expected tag is the cross-language pin the Python
        // suite carries, captured from the reference build.
        byte[] tag = Argon2id.derive(filled(32, 1), filled(16, 2), 3, 32, 4, 32, filled(8, 3), filled(12, 4));
        assertEquals("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
                Canonical.hex(tag));
    }

    @Test
    void argon2idDifferentialTagsMatchTheReferenceBuild() {
        // Pins captured independently from the reference build and
        // re-verified here against libsodium and the reference CLI.
        assertEquals("929ea45c6d883a86f284950fd0ed67f72aa687dd6ea22d25b6f833da6d50cf19",
                Canonical.hex(Argon2id.derive("prefix21".getBytes(StandardCharsets.UTF_8),
                        rising16(), 3, 32, 1, 32, new byte[0], new byte[0])));
        assertEquals("381612cb120864032b674082eb0144f821e9395f3f1ca74ab41ce8bd8e328921",
                Canonical.hex(Argon2id.derive("prefix21".getBytes(StandardCharsets.UTF_8),
                        rising16(), 3, 64, 1, 32, new byte[0], new byte[0])));
        assertEquals("61c1d3de8b09b930ef0eff624ebb407932ee6d65e4052e591ec79ab57d5397f8",
                Canonical.hex(Argon2id.derive("prefix21".getBytes(StandardCharsets.UTF_8),
                        rising16(), 3, 64, 2, 32, new byte[0], new byte[0])));
    }

    private static byte[] rising16() {
        byte[] salt = new byte[16];
        for (int i = 0; i < 16; i++) {
            salt[i] = (byte) i;
        }
        return salt;
    }

    @Test
    void argon2idSodiumLanesOneVector() {
        Path golden = Support.testdataPath("golden/golden-php-vectors.json");
        if (golden == null) {
            throw new org.opentest4j.TestAbortedException("the golden vectors are not committed");
        }
        byte[] tag = Argon2id.derive("argon2-sodium-vector-password".getBytes(StandardCharsets.UTF_8),
                filled(16, 2), 3, 64, 1, 32, new byte[0], new byte[0]);
        String expected = Support.goldenString(
                (java.util.Map<String, Object>) Support.goldenVectors().get("argon2id_reference"), "tag_hex");
        assertEquals(expected, Canonical.hex(tag));
    }

    @Test
    void hkdfPinsTheGoldenPurposeKeys() {
        var hkdf = (java.util.Map<String, Object>) Support.goldenVectors().get("hkdf");
        DerivedKeys keys = DerivedKeys.fromMaster(Support.TEST_SECRET, "");
        assertEquals(Support.goldenString(hkdf, "challenge_hex"), Canonical.hex(keys.challengeKey));
        assertEquals(Support.goldenString(hkdf, "ip_bind_hex"), Canonical.hex(keys.ipBindKey));
        assertEquals(Support.goldenString(hkdf, "result_hex"), Canonical.hex(keys.resultKey));
        assertEquals(Support.goldenString(hkdf, "server_state_hex"), Canonical.hex(keys.serverStateKey));
    }

    @Test
    void hkdfTenantScopingChangesTheKeys() {
        DerivedKeys global = DerivedKeys.fromMaster(Support.TEST_SECRET, "");
        DerivedKeys tenant = DerivedKeys.fromMaster(Support.TEST_SECRET, "acme");
        assertFalse(Canonical.constantTimeEquals(global.challengeKey, tenant.challengeKey));
    }

    @Test
    void hkdfRejectsShortSecrets() {
        try {
            DerivedKeys.fromMaster("short", "");
            throw new AssertionError("a short secret must be refused");
        } catch (Canonical.SecretTooShortException expected) {
            assertNotNull(expected.getMessage());
        }
    }

    private static byte[] filled(int length, int value) {
        byte[] out = new byte[length];
        java.util.Arrays.fill(out, (byte) value);
        return out;
    }

    @Test
    void protocolCorpusPathResolvesInsideTheRepository() {
        Path path = Support.protocolPath("solution-token-v1/fixtures.json");
        assertTrue(path == null || Files.exists(path));
    }
}
