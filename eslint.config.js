import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default [
  {
    ignores: ["dist/**", "worker/dist/**", "server/dist/**", "node_modules/**", "coverage/**"]
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: {
        Blob: "readonly",
        Buffer: "readonly",
        Headers: "readonly",
        HTMLInputElement: "readonly",
        HTMLTextAreaElement: "readonly",
        MessageEvent: "readonly",
        MutationObserver: "readonly",
        Node: "readonly",
        Response: "readonly",
        SubtleCrypto: "readonly",
        TextDecoder: "readonly",
        TextEncoder: "readonly",
        URL: "readonly",
        URLSearchParams: "readonly",
        WebSocket: "readonly",
        WebSocketPair: "readonly",
        atob: "readonly",
        btoa: "readonly",
        clearInterval: "readonly",
        console: "readonly",
        crypto: "readonly",
        document: "readonly",
        fetch: "readonly",
        globalThis: "readonly",
        history: "readonly",
        navigator: "readonly",
        process: "readonly",
        setInterval: "readonly",
        setTimeout: "readonly",
        window: "readonly"
      }
    },
    rules: {
      "no-console": ["warn", { "allow": ["warn", "error"] }],
      "@typescript-eslint/no-unused-vars": ["error", { "argsIgnorePattern": "^_" }]
    }
  }
];
