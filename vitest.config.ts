import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Tests sit next to the code, as in the vendored copies. The `.live`
    // tests skip themselves unless a Bee node is reachable (BEE_API_URL,
    // default http://localhost:1633) in the state they need.
    include: ["src/**/*.test.ts"],
  },
});
