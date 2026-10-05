import { defineConfig } from "vitest/config";
import solid from "vite-plugin-solid";

export default defineConfig({
  plugins: [solid()],
  test: {
    environment: "happy-dom",
    include: ["test/**/*.test.tsx"],
    globals: false,
  },
  build: {
    rollupOptions: {
      external: ["solid-js", "@kiwicaptcha/client-core"],
    },
  },
});
