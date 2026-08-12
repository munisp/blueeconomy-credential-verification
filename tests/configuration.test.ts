import assert from "node:assert/strict";
import test from "node:test";

import { parseConfiguration } from "../src/verify.js";

test("rejects a non-HTTPS JWKS URL", () => {
  assert.throws(
    () =>
      parseConfiguration([
        "--credential", "approved.jwt",
        "--issuer", "https://issuer.example.invalid",
        "--audience", "blueeconomy-platform",
        "--jwks-url", "http://issuer.example.invalid/keys",
        "--evidence", "evidence.json",
      ]),
    /jwks-url must be an HTTPS URL/,
  );
});

test("rejects missing credential argument", () => {
  assert.throws(
    () =>
      parseConfiguration([
        "--issuer", "https://issuer.example.invalid",
        "--audience", "blueeconomy-platform",
        "--jwks-url", "https://issuer.example.invalid/keys",
        "--evidence", "evidence.json",
      ]),
    /--credential is required/,
  );
});
