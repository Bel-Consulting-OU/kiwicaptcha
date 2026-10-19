import { NativeModules, TurboModuleRegistry } from "react-native";
import type { NativeKiwiSolver } from "./types.js";

/**
 * Native module resolution for the KiwiCaptchaSolver bridge
 * (docs/NATIVE.md is the authoritative spec).
 *
 * The module this resolves is shipped in this package: `android/`
 * (Kotlin, `KiwiSolverPackage` -> `KiwiCaptchaSolverModule`, MessageDigest
 * SHA-256 on a background thread) and `ios/` (Swift, CryptoKit SHA-256
 * on a background queue, registered via KiwiCaptchaSolverBridge.m).
 *
 * The lookup covers every supported React Native setup:
 * 1. `TurboModuleRegistry` — the New Architecture, including the
 *    legacy-module interop proxy (RN 0.74+ serves a classic
 *    ReactPackage module through it by default);
 * 2. `NativeModules` — the classic bridge (and RN 0.73 and older
 *    bridge-mode builds, where no turbo proxy exists).
 *
 * Resolution is uncached on purpose: an absent module stays absent and
 * a linked module stays linked for the life of a session, while tests
 * install and remove stand-ins freely.
 */

/** The exact bridge name both native modules register under. */
export const NATIVE_MODULE_NAME = "KiwiCaptchaSolver";

/** The react-native bridge module, or null when the app has none. */
export function nativeSolver(): NativeKiwiSolver | null {
  const registry = TurboModuleRegistry as
    | { get?: (name: string) => unknown }
    | null
    | undefined;
  try {
    const turbo = typeof registry?.get === "function" ? registry.get(NATIVE_MODULE_NAME) : null;
    if (turbo) return turbo as NativeKiwiSolver;
  } catch {
    // No registry on this build (old bridge mode) or the lookup was
    // refused: fall through to the classic bridge.
  }
  const modules = NativeModules as Record<string, NativeKiwiSolver | undefined>;
  return modules[NATIVE_MODULE_NAME] ?? null;
}
