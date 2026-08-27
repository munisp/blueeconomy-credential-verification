import { createHash, sign as ed25519Sign, verify as ed25519Verify, type KeyObject } from "node:crypto";
import { asJsonValue, canonicalizeBytes, type JsonValue } from "./jcs.js";
import { decodeBase58Btc, encodeBase58Btc } from "./multibase.js";
import { DATA_INTEGRITY_PROOF_TYPE, EDDSA_JCS_2022_CRYPTOSUITE, type DataIntegrityProofShape } from "./types.js";

/**
 * Data Integrity proof with the Ed25519 eddsa-jcs-2022 cryptosuite
 * (W3C CCG Data Integrity EdDSA Cryptosuites v1.0): the unsecured document
 * and the proof options are canonicalized with JCS (RFC 8785), each hashed
 * with SHA-256, concatenated (proof hash first) and signed with Ed25519.
 * All operations are offline; no network access is required.
 */

export interface ProofOptions {
  created: string;
  verificationMethod: string;
  proofPurpose: "assertionMethod";
}

export function addDataIntegrityProof(
  unsecuredDocument: Record<string, JsonValue>,
  options: ProofOptions,
  privateKey: KeyObject,
): DataIntegrityProofShape {
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error("eddsa-jcs-2022 requires an Ed25519 private key");
  }
  if ("proof" in unsecuredDocument) {
    throw new Error("unsecured document must not already contain a proof");
  }
  const proofOptions: Record<string, JsonValue> = {
    type: DATA_INTEGRITY_PROOF_TYPE,
    cryptosuite: EDDSA_JCS_2022_CRYPTOSUITE,
    created: options.created,
    verificationMethod: options.verificationMethod,
    proofPurpose: options.proofPurpose,
  };
  const signature = ed25519Sign(null, hashData(proofOptions, unsecuredDocument), privateKey);
  return { ...proofOptions, proofValue: encodeBase58Btc(signature) } as DataIntegrityProofShape;
}

export function verifyDataIntegrityProof(
  securedDocument: Record<string, JsonValue>,
  publicKey: KeyObject,
): DataIntegrityProofShape {
  if (publicKey.asymmetricKeyType !== "ed25519") {
    throw new Error("eddsa-jcs-2022 requires an Ed25519 public key");
  }
  const proof = securedDocument["proof"];
  if (typeof proof !== "object" || proof === null || Array.isArray(proof)) {
    throw new Error("credential is missing a Data Integrity proof");
  }
  const shape = proof as Record<string, JsonValue>;
  if (shape["type"] !== DATA_INTEGRITY_PROOF_TYPE || shape["cryptosuite"] !== EDDSA_JCS_2022_CRYPTOSUITE) {
    throw new Error("unsupported proof type or cryptosuite");
  }
  for (const field of ["created", "verificationMethod", "proofPurpose", "proofValue"] as const) {
    if (typeof shape[field] !== "string" || (shape[field] as string).length === 0) {
      throw new Error(`proof ${field} must be non-empty text`);
    }
  }
  if (shape["proofPurpose"] !== "assertionMethod") {
    throw new Error("proof purpose must be assertionMethod");
  }
  const signature = decodeBase58Btc(shape["proofValue"] as string);
  if (signature.length !== 64) {
    throw new Error("proof value is not a 64-byte Ed25519 signature");
  }
  const proofOptions: Record<string, JsonValue> = {
    type: DATA_INTEGRITY_PROOF_TYPE,
    cryptosuite: EDDSA_JCS_2022_CRYPTOSUITE,
    created: shape["created"] as string,
    verificationMethod: shape["verificationMethod"] as string,
    proofPurpose: "assertionMethod",
  };
  const unsecured = { ...securedDocument };
  delete unsecured["proof"];
  if (!ed25519Verify(null, hashData(proofOptions, unsecured), publicKey, signature)) {
    throw new Error("credential Data Integrity proof verification failed");
  }
  return proof as unknown as DataIntegrityProofShape;
}

function hashData(proofOptions: Record<string, JsonValue>, unsecuredDocument: Record<string, JsonValue>): Buffer {
  const proofHash = createHash("sha256").update(canonicalizeBytes(asJsonValue(proofOptions))).digest();
  const documentHash = createHash("sha256").update(canonicalizeBytes(asJsonValue(unsecuredDocument))).digest();
  return Buffer.concat([proofHash, documentHash]);
}
