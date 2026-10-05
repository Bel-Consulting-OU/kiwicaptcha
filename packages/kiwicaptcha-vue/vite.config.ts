import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  plugins: [vue()],
  build: {
    lib: {
      entry: "src/index.ts",
      formats: ["es"],
      fileName: "index",
    },
    rollupOptions: {
      external: ["vue", "@kiwicaptcha/client-core"],
    },
  },
  test: {
    environment: "happy-dom",
    include: ["test/**/*.test.ts"],
    globals: false,
  },
});
