import { defineConfig } from 'vite';
import angular from '@analogjs/vite-plugin-angular';

// The Angular plugin applies the compiler transform (template and
// query lowering). The esbuild block pins the class-field semantics the
// workspace tsconfig declares, so signal queries keep assignment
// semantics under the test transform. jsdom plus the zone.js setup in
// vitest.setup.ts provide the TestBed environment.
export default defineConfig({
  plugins: [angular({ tsconfig: './tsconfig.spec.json' })],
  esbuild: {
    tsconfigRaw: {
      compilerOptions: {
        experimentalDecorators: true,
        useDefineForClassFields: false,
        target: 'ES2022',
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./vitest.setup.ts'],
    include: ['src/**/*.spec.ts'],
    testTimeout: 30000,
  },
});
