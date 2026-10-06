package com.kiwicaptcha.servlet;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The shared client-IP test vectors, asserted against the JVM
 * resolver. Every SDK runs the same scenarios from
 * tools/client-ip/test-vectors.json, so one request resolves to one
 * canonical IP everywhere.
 */
class ClientIpResolverTest {
    @SuppressWarnings("unchecked")
    private static Map<String, Object> vectors() throws Exception {
        Path path = Paths.get("..", "..", "..", "tools", "client-ip", "test-vectors.json")
                .toAbsolutePath().normalize();
        assertTrue(Files.exists(path), "shared vectors found at " + path);
        return (Map<String, Object>) com.kiwicaptcha.StrictJson.decode(
                Files.readAllBytes(path));
    }

    @SuppressWarnings("unchecked")
    private static List<String> strings(Object value) {
        List<String> out = new ArrayList<>();
        if (value instanceof List<?> list) {
            for (Object entry : list) {
                out.add(String.valueOf(entry));
            }
        }
        return out;
    }

    @Test
    void sharedCidrCases() throws Exception {
        for (Object row : (List<Object>) vectors().get("cidr_cases")) {
            Map<String, Object> caseRow = (Map<String, Object>) row;
            boolean matched = ClientIpResolver.inTrusted(
                    String.valueOf(caseRow.get("ip")), List.of(String.valueOf(caseRow.get("cidr"))));
            assertEquals(caseRow.get("matches"), matched,
                    "cidr " + caseRow.get("cidr") + " vs " + caseRow.get("ip"));
        }
    }

    @Test
    void sharedScenarios() throws Exception {
        for (Object row : (List<Object>) vectors().get("scenarios")) {
            Map<String, Object> scenario = (Map<String, Object>) row;
            // The servlet surface sees every header line, so the
            // duplicate scenario asserts the fail-closed expectation.
            String resolved = ClientIpResolver.resolve(
                    String.valueOf(scenario.get("peer")),
                    strings(scenario.get("xff_lines")),
                    (String) scenario.get("real_ip"),
                    strings(scenario.get("trusted")));
            assertEquals(String.valueOf(scenario.get("expected")), resolved,
                    "scenario " + scenario.get("id"));
        }
    }

    @Test
    void canonicalIpEdges() {
        assertEquals("192.0.2.10", ClientIpResolver.canonicalIp(" 192.0.2.10:4711 "));
        assertEquals("2001:db8::1", ClientIpResolver.canonicalIp("[2001:DB8::1]"));
        assertEquals("2001:db8::1", ClientIpResolver.canonicalIp("[2001:db8::1]:4711"));
        assertEquals("198.51.100.5", ClientIpResolver.canonicalIp("::ffff:198.51.100.5"));
        assertEquals("2001:db8::1", ClientIpResolver.canonicalIp("2001:0db8:0:0:0:0:0:1"));
        assertNull(ClientIpResolver.canonicalIp(""));
        assertNull(ClientIpResolver.canonicalIp("unknown"));
        assertNull(ClientIpResolver.canonicalIp("_obfuscated"));
        assertNull(ClientIpResolver.canonicalIp("[2001:db8::1]:notaport"));
        assertNull(ClientIpResolver.canonicalIp("[2001:db8::1]garbage"));
        assertNull(ClientIpResolver.canonicalIp("1.2.3.4:0"));
        assertNull(ClientIpResolver.canonicalIp("0:1.2.3.4"));
        assertNull(ClientIpResolver.canonicalIp("1.2.3.4.5"));
        assertNull(ClientIpResolver.canonicalIp("3232235521"));
        assertNull(ClientIpResolver.canonicalIp("01.2.3.4"));
    }
}
