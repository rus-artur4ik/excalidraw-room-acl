import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    environment: "node",
    env: {
      GOOGLE_APPLICATION_CREDENTIALS: "test-credentials.json",
      FIREBASE_PROJECT_ID: "test-project",
    },
  },
});
