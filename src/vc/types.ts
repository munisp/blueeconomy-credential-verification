import type { JsonValue } from "./jcs.js";

/**
 * W3C Verifiable Credentials Data Model 2.0 types for the Nigerian seafarer
 * Certificate of Competency (CoC) wallet credential profile. NIMASA is the
 * issuing authority; the credential subject carries the STCW-aligned capacity
 * and limitation set.
 */

export const VC2_CONTEXT = "https://www.w3.org/ns/credentials/v2" as const;
export const SEAFARER_COC_TYPE = "SeafarerCoC" as const;
export const DATA_INTEGRITY_PROOF_TYPE = "DataIntegrityProof" as const;
export const EDDSA_JCS_2022_CRYPTOSUITE = "eddsa-jcs-2022" as const;

/** STCW-aligned CoC capacity and limitation set. */
export interface SeafarerCoCSubject {
  id: string;
  type: "Seafarer";
  seafarerReferenceNumber: string;
  capacity: string;
  stcwRegulation: string;
  limitations: string[];
  nationality?: string;
  name?: string;
}

export interface CredentialStatusEntry {
  type: "BitstringStatusListEntry";
  statusPurpose: "revocation";
  statusListCredential: string;
  statusListIndex: string;
}

export interface DataIntegrityProofShape {
  type: typeof DATA_INTEGRITY_PROOF_TYPE;
  cryptosuite: typeof EDDSA_JCS_2022_CRYPTOSUITE;
  created: string;
  verificationMethod: string;
  proofPurpose: "assertionMethod";
  proofValue: string;
}

export interface SeafarerCoCCredential {
  "@context": [typeof VC2_CONTEXT];
  id: string;
  type: ["VerifiableCredential", typeof SEAFARER_COC_TYPE];
  issuer: string;
  validFrom: string;
  validUntil: string;
  credentialSubject: SeafarerCoCSubject;
  credentialStatus: CredentialStatusEntry;
  proof: DataIntegrityProofShape;
}

export type UnsignedSeafarerCoCCredential = Omit<SeafarerCoCCredential, "proof">;

export function asJsonObject(value: unknown): Record<string, JsonValue> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("credential value must be a JSON object");
  }
  return value as Record<string, JsonValue>;
}
