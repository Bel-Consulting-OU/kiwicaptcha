package com.kiwicaptcha;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The sidecar delegation plane: the spawned kiwicaptcha-verifier (the
 * full Rust core with the real execution verifier) fronts an
 * execution-armed challenge; the SDK's fail-closed default refuses it,
 * the sidecar policy delegates and accepts. Skipped where the verifier
 * crate is unavailable.
 */
class ExecutionPolicyTest {

    private static final Path SIDECAR =
            Path.of("..", "..", "..", "target", "debug", "kiwicaptcha-verifier").normalize();
    private static final String SECRET = "jvm-sidecar-delegation-0123456789abcdef";

    @Test
    void failClosedDefaultThenSidecarDelegation() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(sidecarBuilt(), "the verifier crate did not build");
        Path store = Files.createTempDirectory("kiwi-sidecar-");
        int port = freePort();

        // The armed record + its browser-equivalent executed evidence,
        // minted by the core and persisted into the sidecar's own file
        // store by the store's own writer.
        Process helper = new ProcessBuilder(SIDECAR.toString(), "exec-evidence",
                "--secret", SECRET, "--scope", "login", "--action", "login-action",
                "--version", "1", "--store-dir", store.toString())
                .redirectErrorStream(true).start();
        String docLine;
        try (var in = helper.inputReader()) {
            docLine = in.readLine();
        }
        assertTrue(helper.waitFor(60, TimeUnit.SECONDS), "the evidence helper finished");
        JsonObject doc = JsonObject.parseObject(docLine);
        JsonObject recordJson = (JsonObject) doc.get("record");
        String trace = (String) doc.get("trace");
        String digest = (String) doc.get("digest");
        ChallengeRecord record = ChallengeRecord.parse(recordJson.encode().getBytes());
        assertFalse(record.executionProgram.isEmpty(), "the minted record is execution-armed");

        ProcessBuilder sidecarBuilder = new ProcessBuilder(SIDECAR.toString());
        sidecarBuilder.environment().putAll(Map.of(
                "KIWI_LISTEN", "http://127.0.0.1:" + port,
                "KIWI_SECRET", SECRET,
                "KIWI_STORE", "file=" + store,
                "KIWI_BINDING", "none",
                "KIWI_PROFILE", "sha16"));
        Process sidecar = sidecarBuilder.inheritIO().start();
        String base = "http://127.0.0.1:" + port;
        boolean healthy = false;
        for (int i = 0; i < 100 && !healthy; i++) {
            try {
                HttpResponse<String> answer = HttpClient.newHttpClient().send(
                        HttpRequest.newBuilder(URI.create(base + "/healthz"))
                                .timeout(Duration.ofSeconds(1)).GET().build(),
                        HttpResponse.BodyHandlers.ofString());
                healthy = answer.statusCode() == 200;
            } catch (Exception e) {
                Thread.sleep(150);
            }
        }
        assertTrue(healthy, "the sidecar never answered /healthz");
        try {
            String token = SolutionToken.create(record.nonce,
                    Support.solveSha(record.prefix, record.salt, record.targetBits), 5000,
                    JsonObject.of(), digest, trace, "").encode();

            // One fresh verifier and record copy per leg: the local
            // one-shot bookkeeping of a refused leg must never shadow
            // the next leg.
            java.util.function.Function<ExecutionPolicy, VerifyOutcome> leg = (policy) -> {
                Verifier verifier = Support.newTestVerifier(new Verifier.Config(),
                        java.time.Instant.now().getEpochSecond());
                Support.storeRecord(verifier.storage(), record);
                Verifier.Options options = new Verifier.Options();
                options.secretKey = SECRET;
                options.expectedScope = "login";
                options.clientIp = Support.TEST_CLIENT_IP;
                options.executionPolicy = policy;
                return verifier.verify(token, options);
            };

            // The fail-closed default: the armed record refuses exactly
            // as before the delegation plane existed.
            VerifyOutcome refused = leg.apply(null);
            assertFalse(refused.valid);
            assertEquals(VerifyError.EXECUTION_MISMATCH, refused.error);

            // The sidecar policy: the delegation accepts.
            VerifyOutcome accepted = leg.apply(new ExecutionPolicy(base, "", 5000));
            assertTrue(accepted.valid, "the delegation must accept: " + accepted.error);

            // Single-use: the sidecar consumed; a replay never re-accepts.
            VerifyOutcome replay = leg.apply(new ExecutionPolicy(base, "", 5000));
            assertFalse(replay.valid);
            assertTrue(replay.error == VerifyError.ALREADY_CONSUMED
                    || replay.error == VerifyError.RECORD_NOT_FOUND,
                    "the replay answers the consumed vocabulary: " + replay.error);

            // An unreachable sidecar answers the retry disposition.
            VerifyOutcome down = leg.apply(new ExecutionPolicy("http://127.0.0.1:1", "", 300));
            assertFalse(down.valid);
            assertEquals(VerifyError.STORAGE_UNAVAILABLE, down.error);
        } finally {
            sidecar.destroy();
            sidecar.waitFor(5, TimeUnit.SECONDS);
        }
    }

    private static boolean sidecarBuilt() {
        if (!Files.exists(SIDECAR)) {
            return exec("cargo", "build", "-q", "-p", "kiwicaptcha-verifier", "--features", "test-fixtures");
        }
        // The test-fixtures feature only adds the evidence subcommand;
        // rebuild with it so the helper role is present too.
        return exec("cargo", "build", "-q", "-p", "kiwicaptcha-verifier", "--features", "test-fixtures");
    }

    private static boolean exec(String... command) {
        try {
            new ProcessBuilder(command).directory(new File("..", ".."))
                    .start().waitFor(10, TimeUnit.MINUTES);
            return Files.exists(SIDECAR);
        } catch (Exception e) {
            return false;
        }
    }

    private static int freePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
