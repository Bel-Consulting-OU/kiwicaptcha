/**
 * The react-native stand-in the Jest suite maps "react-native" onto:
 * NativeModules starts empty (no solver linked) and each test installs
 * what it needs.
 */
export const NativeModules: {
  KiwiCaptchaSolver?: {
    solve(challengeJson: string): Promise<string>;
  };
} = {};

export function __setNativeSolver(solver: { solve(challengeJson: string): Promise<string> } | null): void {
  if (solver === null) {
    delete NativeModules.KiwiCaptchaSolver;
  } else {
    NativeModules.KiwiCaptchaSolver = solver;
  }
}
