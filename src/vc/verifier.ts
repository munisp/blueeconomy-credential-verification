import type { KeyObject } from "node:crypto";
import { verifyDataIntegrityProof } from "./data-integrity.js";
import { asJsonValue, type JsonValue } from "./jcs.js";
import { decodeBitstring, getStatusBit, assertStatusListCredential, type BitstringStatusListCredential } from "./status-list.js";
import { SEAFARER_COC_TYPE, VC2_CONTEXT, type SeafarerCoCCredential } from "./types.js";

/**
 * Offline-capable verifier for NIMASA seafarer CoC credentials. Verification
 * requires only the issuer's Ed25519 public key and a Bitstring Status List
 * snapshot supplied by the caller; this module performs no network I/O.
 */

export interface VerificationRequest {
  credential: unknown;
  issuerPublicKey: KeyObject;
  /** Expected issuer DID (did:web). */
  expectedIssuer: string;
  /** Holder DID/identifier the credential must be bound to. */
  expectedHolderId: string;
  /** Snapshot of the revocation status list credential. */
  statusListCredential: unknown;
  now?: Date;
}

export interface VerificationResult {
  credentialId: string;
  issuer: string;
  holderId: string;
  capacity: string;
  stcwRegulation: string;
  validUntil: string;
  verificationMethod: string;
  checkedStatusListIndex: number;
}

export function verifyCoCCredential(request: VerificationRequest): VerificationResult {
  const now = request.now ?? new Date();
  if (!Number.isFinite(now.getTime())) throw new Error("verification time must be valid");
  const credential = assertCoCCredentialShape(request.credential);
  if (credential.issuer !== request.expectedIssuer) {
    throw new Error("credential issuer does not match the expected NIMASA issuer");
  }
  if (credential.credentialSubject.id !== request.expectedHolderId) {
    throw new Error("credential is not bound to the presented holder");
  }

  const proof = verifyDataIntegrityProof(asJsonValue(credential) as Record<string, JsonValue>, request.issuerPublicKey);
  if (!proof.verificationMethod.startsWith(`${credential.issuer}#`)) {
    throw new Error("proof verification method does not belong to the credential issuer");
  }

  const validFrom = Date.parse(credential.validFrom);
  const validUntil = Date.parse(credential.validUntil);
  if (now.getTime() < validFrom) throw new Error("credential is not yet valid");
  if (now.getTime() >= validUntil) throw new Error("credential is expired");

  const statusList = assertStatusListCredential(request.statusListCredential);
  assertStatusListApplies(credential, statusList, request.issuerPublicKey, now);
  const index = Number.parseInt(credential.credentialStatus.statusListIndex, 10);
  const bits = decodeBitstring(statusList.credentialSubject.encodedList);
  if (getStatusBit(bits, index)) {
    throw new Error("credential has been revoked by the issuer");
  }

  return {
    credentialId: credential.id,
    issuer: credential.issuer,
    holderId: credential.credentialSubject.id,
    capacity: credential.credentialSubject.capacity,
    stcwRegulation: credential.credentialSubject.stcwRegulation,
    validUntil: credential.validUntil,
    verificationMethod: proof.verificationMethod,
    checkedStatusListIndex: index,
  };
}

function assertStatusListApplies(
  credential: SeafarerCoCCredential,
  statusList: BitstringStatusListCredential,
  issuerPublicKey: KeyObject,
  now: Date,
): void {
  if (statusList.id !== credential.credentialStatus.statusListCredential) {
    throw new Error("status list credential does not match the credential status entry");
  }
  if (statusList.issuer !== credential.issuer) {
    throw new Error("status list credential issuer does not match the credential issuer");
  }
  if (statusList.proof === undefined) {
    throw new Error("status list credential is unsigned; refusing unauthenticated status data");
  }
  verifyDataIntegrityProof(asJsonValue(statusList) as Record<string, JsonValue>, issuerPublicKey);
  if (now.getTime() < Date.parse(statusList.validFrom)) {
    throw new Error("status list credential is not yet valid");
  }
}

export function assertCoCCredentialShape(value: unknown): SeafarerCoCCredential {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("credential must be a JSON object");
  }
  const candidate = value as Partial<SeafarerCoCCredential>;
  const context = candidate["@context"];
  if (!Array.isArray(context) || context.length !== 1 || context[0] !== VC2_CONTEXT) {
    throw new Error("credential @context must be exactly [https://www.w3.org/ns/credentials/v2]");
  }
  if (!Array.isArray(candidate.type) || candidate.type.length !== 2 || candidate.type[0] !== "VerifiableCredential" || candidate.type[1] !== SEAFARER_COC_TYPE) {
    throw new Error("credential type must be [VerifiableCredential, SeafarerCoC]");
  }
  if (typeof candidate.id !== "string" || candidate.id.length === 0 || candidate.id.length > 256) {
    throw new Error("credential id must be non-empty text of at most 256 characters");
  }
  if (typeof candidate.issuer !== "string" || !candidate.issuer.startsWith("did:web:")) {
    throw new Error("credential issuer must be a did:web identifier");
  }
  if (typeof candidate.validFrom !== "string" || !Number.isFinite(Date.parse(candidate.validFrom))) {
    throw new Error("credential validFrom must be a valid date-time");
  }
  if (typeof candidate.validUntil !== "string" || !Number.isFinite(Date.parse(candidate.validUntil))) {
    throw new Error("credential validUntil must be a valid date-time");
  }
  const subject = candidate.credentialSubject;
  if (typeof subject !== "object" || subject === null) throw new Error("credentialSubject is required");
  if (typeof subject.id !== "string" || subject.id.length === 0) throw new Error("credentialSubject.id is required for holder binding");
  if (subject.type !== "Seafarer") throw new Error("credentialSubject.type must be Seafarer");
  for (const field of ["seafarerReferenceNumber", "capacity", "stcwRegulation"] as const) {
    if (typeof subject[field] !== "string" || (subject[field] as string).length === 0) {
      throw new Error(`credentialSubject.${field} is required`);
    }
  }
  if (!Array.isArray(subject.limitations) || subject.limitations.some((entry) => typeof entry !== "string")) {
    throw new Error("credentialSubject.limitations must be an array of text");
  }
  const status = candidate.credentialStatus;
  if (typeof status !== "object" || status === null) throw new Error("credentialStatus is required");
  if (status.type !== "BitstringStatusListEntry" || status.statusPurpose !== "revocation") {
    throw new Error("credentialStatus must be a revocation BitstringStatusListEntry");
  }
  if (typeof status.statusListCredential !== "string" || status.statusListCredential.length === 0) {
    throw new Error("credentialStatus.statusListCredential is required");
  }
  if (typeof status.statusListIndex !== "string" || !/^[0-9]+$/.test(status.statusListIndex)) {
    throw new Error("credentialStatus.statusListIndex must be a decimal integer string");
  }
  return candidate as SeafarerCoCCredential;
}
