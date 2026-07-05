import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    environment: "node",
    retry: process.env.CI ? 2 : 0,
    reporters: process.env.CI
      ? ["default", ["junit", { outputFile: "./test-results/junit.xml" }]]
      : ["default"],
    env: {
      GOOGLE_APPLICATION_CREDENTIALS: "test-credentials.json",
      FIREBASE_PROJECT_ID: "test-project",
    },
  },
});
