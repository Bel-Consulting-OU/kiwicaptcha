/**
 * The react-native stand-in the Jest suite maps "react-native" onto:
 * NativeModules starts empty (no solver linked) and each test installs
 * what it needs. The solver shape mirrors NativeKiwiSolver, including
 * the optional progress channel. TurboModuleRegistry models a modern RN
 * runtime where the registry and the classic bridge see the same
 * module: the resolver in src/native.ts consults the registry first,
 * then NativeModules.
 */
export interface MockKiwiSolver {
  solve(challengeJson: string): Promise<string>;
  solveWithProgress?(
    challengeJson: string,
    onProgress: (info: { attempted: number }) => void,
  ): Promise<string>;
}

export const NativeModules: {
  KiwiCaptchaSolver?: MockKiwiSolver;
} = {};

export const TurboModuleRegistry = {
  get(name: string): unknown {
    return NativeModules[name as keyof typeof NativeModules] ?? null;
  },
};

export function __setNativeSolver(solver: MockKiwiSolver | null): void {
  if (solver === null) {
    delete NativeModules.KiwiCaptchaSolver;
  } else {
    NativeModules.KiwiCaptchaSolver = solver;
  }
}
