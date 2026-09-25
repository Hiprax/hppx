import type { Config } from "jest";

const config: Config = {
  testEnvironment: "node",
  roots: ["<rootDir>/tests"],
  transform: {
    "^.+\\.(t|j)sx?$": ["ts-jest", { tsconfig: "tsconfig.json" }],
  },
  moduleFileExtensions: ["ts", "tsx", "js", "jsx", "json", "node"],
  verbose: true,
  // Auto-restore mocks created with jest.spyOn() between tests. This makes
  // console-spy patterns deterministic and prevents stderr leaks if a test
  // forgets to restore manually.
  restoreMocks: true,
  collectCoverage: true,
  collectCoverageFrom: ["src/**/*.ts"],
  coverageReporters: ["text", "lcov"],
  // Measured coverage floor (truncated to two decimals): it only ever moves up.
  coverageThreshold: {
    global: { statements: 99.76, branches: 95.94, functions: 100, lines: 100 },
  },
};

export default config;
