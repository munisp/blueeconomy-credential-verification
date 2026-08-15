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
        "--algorithm", "RS256",
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
        "--algorithm", "RS256",
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
        "--algorithm", "RS256",
        "--evidence", "evidence.json",
      ]),
    /evidence path or staging path must not overwrite the credential input/,
  );
});

test("rejects an unapproved JWT algorithm", () => {
  assert.throws(
    () =>
      parseConfiguration([
        "--credential", "approved.jwt",
        "--issuer", "https://issuer.example.invalid",
        "--audience", "blueeconomy-platform",
        "--jwks-url", "https://issuer.example.invalid/keys",
        "--algorithm", "HS256",
        "--evidence", "evidence.json",
      ]),
    /algorithm must be one of RS256, ES256 or EdDSA/,
  );
});

test("accepts explicit JTI requirement", () => {
  const configuration = parseConfiguration([
    "--credential", "approved.jwt",
    "--issuer", "https://issuer.example.invalid",
    "--audience", "blueeconomy-platform",
    "--jwks-url", "https://issuer.example.invalid/keys",
    "--algorithm", "RS256",
    "--evidence", "evidence.json",
    "--require-jti", "true",
  ]);
  assert.equal(configuration.requireJti, true);
});

test("rejects invalid JTI requirement value", () => {
  assert.throws(
    () =>
      parseConfiguration([
        "--credential", "approved.jwt",
        "--issuer", "https://issuer.example.invalid",
        "--audience", "blueeconomy-platform",
        "--jwks-url", "https://issuer.example.invalid/keys",
        "--algorithm", "RS256",
        "--evidence", "evidence.json",
        "--require-jti", "yes",
      ]),
    /--require-jti must be true or false/,
  );
});

test("rejects missing credential argument", () => {
  assert.throws(
    () =>
      parseConfiguration([
        "--issuer", "https://issuer.example.invalid",
        "--audience", "blueeconomy-platform",
        "--jwks-url", "https://issuer.example.invalid/keys",
        "--algorithm", "RS256",
        "--evidence", "evidence.json",
      ]),
    /--credential is required/,
  );
});
