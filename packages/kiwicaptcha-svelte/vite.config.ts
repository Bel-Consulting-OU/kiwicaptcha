import { defineConfig } from "vitest/config";
import { svelte } from "@sveltejs/vite-plugin-svelte";

export default defineConfig({
  plugins: [svelte()],
  build: {
    lib: {
      entry: "src/index.ts",
      formats: ["es"],
      fileName: "index",
    },
    rollupOptions: {
      external: ["svelte", "@kiwicaptcha/client-core"],
    },
  },
  test: {
    environment: "happy-dom",
    include: ["test/**/*.test.ts"],
    globals: false,
  },
  // Svelte's package exports point node conditions at the server runtime;
  // client mounts need the browser entry.
  resolve: process.env.VITEST ? { conditions: ["browser"] } : undefined,
});
