package com.kiwicaptcha;

import java.util.ArrayList;
import java.util.List;

/**
 * Command kiwicaptcha-doctor validates a kiwicaptcha JVM deployment:
 * the settings shape, the secret length, a full one-shot store
 * roundtrip, the configured scopes and the proof budget of the
 * configured profile.
 *
 * java -jar kiwicaptcha-core.jar --secret "32 bytes or more" \
 *     --store memory:// --scopes login,comment --profile standard
 */
public final class DoctorMain {
    private DoctorMain() {}

    /** Parses the flags, runs every doctor check, and exits 1 on any failure. */
    public static void main(String[] args) {
        String secret = "";
        String storeUrl = "memory://";
        String scopesFlag = "";
        String profile = "standard";
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--secret" -> secret = next(args, ++i);
                case "--store" -> storeUrl = next(args, ++i);
                case "--scopes" -> scopesFlag = next(args, ++i);
                case "--profile" -> profile = next(args, ++i);
                case "--help", "-h" -> {
                    System.out.println("usage: kiwicaptcha-doctor --secret SECRET [--store memory://|redis://host:port]"
                            + " [--scopes a,b] [--profile standard|argon16|argon32|argon64]");
                    return;
                }
                default -> {
                    System.err.println("kiwicaptcha-doctor: unknown flag " + args[i]);
                    System.exit(2);
                }
            }
        }
        List<String> scopes = new ArrayList<>();
        for (String scope : scopesFlag.split(",")) {
            if (!scope.isEmpty()) {
                scopes.add(scope);
            }
        }
        List<Doctor.Check> results = Doctor.run(secret, storeUrl, scopes, profile);
        boolean failed = false;
        for (Doctor.Check result : results) {
            System.out.printf("%s %s: %s%n", result.ok ? "ok  " : "FAIL", result.name, result.detail);
            failed |= !result.ok;
        }
        if (failed) {
            System.out.println("doctor: the deployment needs attention");
            System.exit(1);
        }
        System.out.println("doctor: every check passed");
    }

    private static String next(String[] args, int index) {
        if (index >= args.length) {
            System.err.println("kiwicaptcha-doctor: missing value after " + args[index - 1]);
            System.exit(2);
            return "";
        }
        return args[index];
    }
}
