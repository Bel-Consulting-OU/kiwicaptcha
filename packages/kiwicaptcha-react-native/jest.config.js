/** Jest preset: TypeScript sources, node environment, mocked react-native. */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  roots: ["<rootDir>/test"],
  transform: {
    "^.+\\.ts$": ["ts-jest", { tsconfig: "tsconfig.json" }],
  },
  moduleNameMapper: {
    "^react-native$": "<rootDir>/test/react-native-mock.ts",
    "^(\\.{1,2}/.*)\\.js$": "$1",
  },
  testMatch: ["**/*.test.ts"],
};
