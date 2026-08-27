import { createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from "node:crypto";
import { addDataIntegrityProof } from "./data-integrity.js";
import { asJsonValue, type JsonValue } from "./jcs.js";
import {
  EDDSA_JCS_2022_CRYPTOSUITE,
  SEAFARER_COC_TYPE,
  VC2_CONTEXT,
  type CredentialStatusEntry,
  type SeafarerCoCCredential,
  type SeafarerCoCSubject,
  type UnsignedSeafarerCoCCredential,
} from "./types.js";

/**
 * NIMASA seafarer CoC issuer. Issues W3C VC 2.0 credentials with an Ed25519
 * Data Integrity proof (eddsa-jcs-2022). The issuer performs no network I/O:
 * the DID document / verification method is resolved by relying parties from
 * did:web out of band, and the private key is supplied via configuration.
 */

export interface IssuerConfiguration {
  /** did:web style issuer identifier, e.g. did:web:credentials.nimasa.gov.ng */
  issuerDid: string;
  /** Fully qualified verification method, e.g. did:web:...#ed25519-key-1 */
  verificationMethod: string;
  privateKey: KeyObject;
  /** Absolute URL of the Bitstring Status List credential for revocation. */
  statusListCredentialUrl: string;
}

export interface CoCIssuanceRequest {
  credentialId: string;
  holderId: string;
  seafarerReferenceNumber: string;
  capacity: string;
  stcwRegulation: string;
  limitations: string[];
  statusListIndex: number;
  validFrom: Date;
  validUntil: Date;
  name?: string;
  nationality?: string;
}

export function loadIssuerPrivateKey(pkcs8Pem: string): KeyObject {
  const key = createPrivateKey({ key: pkcs8Pem, format: "pem" });
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error("issuer signing key must be an Ed25519 PKCS#8 PEM");
  }
  return key;
}

export function issuerPublicKey(configuration: IssuerConfiguration): KeyObject {
  return createPublicKey(configuration.privateKey);
}

/** Deterministic key material for isolated test environments only. */
export function generateEphemeralIssuerKeyPair(): { privateKey: KeyObject; publicKey: KeyObject } {
  return generateKeyPairSync("ed25519");
}

export function assertIssuerDid(issuerDid: string): string {
  if (!/^did:web:[A-Za-z0-9._:-]{1,252}$/.test(issuerDid)) {
    throw new Error("issuer DID must be a canonical did:web identifier");
  }
  return issuerDid;
}

export function issueCoCCredential(
  configuration: IssuerConfiguration,
  request: CoCIssuanceRequest,
  now = new Date(),
): SeafarerCoCCredential {
  assertIssuerDid(configuration.issuerDid);
  if (!configuration.verificationMethod.startsWith(`${configuration.issuerDid}#`)) {
    throw new Error("verification method must belong to the issuer DID");
  }
  assertCanonical(request.credentialId, "credential id", 256);
  assertCanonical(request.holderId, "holder id", 256);
  assertCanonical(request.seafarerReferenceNumber, "seafarer reference number", 64);
  assertCanonical(request.capacity, "capacity", 128);
  assertStcwRegulation(request.stcwRegulation);
  if (!Array.isArray(request.limitations) || request.limitations.some((entry) => typeof entry !== "string" || entry.trim() !== entry || entry.length === 0 || entry.length > 256)) {
    throw new Error("limitations must be canonical text of 1-256 characters");
  }
  if (!Number.isInteger(request.statusListIndex) || request.statusListIndex < 0) {
    throw new Error("status list index must be a non-negative integer");
  }
  if (!Number.isFinite(request.validFrom.getTime()) || !Number.isFinite(request.validUntil.getTime())) {
    throw new Error("validity bounds must be valid dates");
  }
  if (request.validUntil.getTime() <= now.getTime()) {
    throw new Error("refusing to issue an already-expired credential");
  }
  if (request.validUntil.getTime() <= request.validFrom.getTime()) {
    throw new Error("validUntil must be after validFrom");
  }

  const subject: SeafarerCoCSubject = {
    id: request.holderId,
    type: "Seafarer",
    seafarerReferenceNumber: request.seafarerReferenceNumber,
    capacity: request.capacity,
    stcwRegulation: request.stcwRegulation,
    limitations: [...request.limitations],
  };
  if (request.name !== undefined) subject.name = assertOptionalText(request.name, "name", 256);
  if (request.nationality !== undefined) subject.nationality = assertOptionalText(request.nationality, "nationality", 64);

  const status: CredentialStatusEntry = {
    type: "BitstringStatusListEntry",
    statusPurpose: "revocation",
    statusListCredential: configuration.statusListCredentialUrl,
    statusListIndex: String(request.statusListIndex),
  };

  const unsigned: UnsignedSeafarerCoCCredential = {
    "@context": [VC2_CONTEXT],
    id: request.credentialId,
    type: ["VerifiableCredential", SEAFARER_COC_TYPE],
    issuer: configuration.issuerDid,
    validFrom: request.validFrom.toISOString(),
    validUntil: request.validUntil.toISOString(),
    credentialSubject: subject,
    credentialStatus: status,
  };
  const proof = addDataIntegrityProof(asJsonValue(unsigned) as Record<string, JsonValue>, {
    created: now.toISOString(),
    verificationMethod: configuration.verificationMethod,
    proofPurpose: "assertionMethod",
  }, configuration.privateKey);
  return { ...unsigned, proof };
}

export const ISSUER_PROOF_SUITE = EDDSA_JCS_2022_CRYPTOSUITE;

function assertStcwRegulation(value: string): void {
  if (!/^STCW (regulation )?[A-Z]+(-[A-Z]+)?\/[0-9]+(\.[0-9]+)?( paragraph [0-9]+)?$/i.test(value)) {
    throw new Error("STCW regulation reference must look like 'STCW regulation II/1'");
  }
}

function assertCanonical(value: string, field: string, maxLength: number): void {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0 || value.length > maxLength) {
    throw new Error(`${field} must be canonical text of 1-${maxLength} characters`);
  }
}

function assertOptionalText(value: string, field: string, maxLength: number): string {
  assertCanonical(value, field, maxLength);
  return value;
}
