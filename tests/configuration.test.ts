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

test("rejects an evidence path that aliases the credential input", () => {
  assert.throws(
    () =>
      parseConfiguration([
        "--credential", "./approved.jwt",
        "--issuer", "https://issuer.example.invalid",
        "--audience", "blueeconomy-platform",
        "--jwks-url", "https://issuer.example.invalid/keys",
        "--evidence", "nested/../approved.jwt",
      ]),
    /evidence path or staging path must not overwrite the credential input/,
  );
});

test("rejects an evidence staging path that aliases the credential input", () => {
  assert.throws(
    () =>
      parseConfiguration([
        "--credential", "evidence.json.tmp",
        "--issuer", "https://issuer.example.invalid",
        "--audience", "blueeconomy-platform",
        "--jwks-url", "https://issuer.example.invalid/keys",
        "--evidence", "evidence.json",
      ]),
    /evidence path or staging path must not overwrite the credential input/,
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
