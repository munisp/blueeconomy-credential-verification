import { createHash } from "node:crypto";
import { SpanKind } from "@opentelemetry/api";
import { withSpan } from "../telemetry/spans.js";

/**
 * TigerBeetle-backed issuance ledger behind a small interface. Every issuance
 * records a double-entry transfer from the NIMASA issuance clearing account
 * to the credential's account; every revocation records the counter-entry in
 * the reverse direction (debit the credential's account, credit the clearing
 * account back), so the ledger balance of a revoked credential returns to
 * zero instead of accumulating a second issuance-direction posting.
 * Transfer IDs are deterministic (SHA-256 of the credential reference +
 * entry kind) so retries are idempotent: TigerBeetle returns `exists` for an
 * identical transfer and the commit is treated as successful. The store fails
 * closed when no TigerBeetle cluster is configured.
 */

export type LedgerEntryKind = "issuance" | "revocation";

export interface LedgerEntry {
  credentialId: string;
  holderReference: string;
  issuer: string;
  kind: LedgerEntryKind;
  occurredAt: string;
}

export interface LedgerCommit {
  transferIdHex: string;
  commitHash: string;
  idempotentReplay: boolean;
}

export interface IssuanceLedger {
  record(entry: LedgerEntry): Promise<LedgerCommit>;
  healthCheck(): Promise<void>;
  close(): Promise<void>;
}

export interface TigerBeetleClientLike {
  createAccounts(batch: unknown[]): Promise<Array<{ index: number; result: number }>>;
  createTransfers(batch: unknown[]): Promise<Array<{ index: number; result: number }>>;
}

export interface TigerBeetleLedgerOptions {
  clusterId: bigint;
  replicaAddresses: string[];
  ledger: number;
  client?: TigerBeetleClientLike;
}

const TB_LEDGER_DEFAULT = 1;
const TB_CODE_ISSUANCE = 7101;
const TB_CODE_REVOCATION = 7102;
/** Account codes: 71xx range reserved for the seafarer credential ledger. */
const NIMASA_CLEARING_ACCOUNT = 7_100_000_001n;

// TigerBeetle CreateTransferStatus.exists === 21
const TB_STATUS_EXISTS = 21;
const TB_STATUS_CREATED = 4_294_967_295;

export function deterministicTransferId(entry: LedgerEntry): bigint {
  const digest = createHash("sha256")
    .update(`blueeconomy.issuance.v1|${entry.kind}|${entry.credentialId}`, "utf8")
    .digest();
  const value = BigInt(`0x${digest.toString("hex")}`) & ((1n << 128n) - 1n);
  if (value === 0n || value === (1n << 128n) - 1n) {
    throw new Error("deterministic transfer id collided with a reserved value");
  }
  return value;
}

/**
 * Full-entropy per-credential account id: the first 16 bytes (128 bits) of
 * SHA-256 over the namespaced credential id. The retired v1 derivation
 * truncated the digest to 8 bytes and reduced it modulo 1e9 (~30 bits of
 * entropy), so distinct credentials could collide onto one account and share
 * revocation postings. The v2 namespace makes this a clean switch: v1 and v2
 * ids never overlap, and v1 accounts are simply never created again
 * (acceptable because the ledger is prototype-phase with no live balances).
 */
export function credentialAccountId(credentialId: string): bigint {
  const digest = createHash("sha256").update(`blueeconomy.credential-account.v2|${credentialId}`, "utf8").digest();
  const value = BigInt(`0x${digest.subarray(0, 16).toString("hex")}`);
  if (value === 0n || value === (1n << 128n) - 1n || value === NIMASA_CLEARING_ACCOUNT) {
    throw new Error("credential account id collided with a reserved value");
  }
  return value;
}

export function ledgerCommitHash(transferId: bigint, entry: LedgerEntry): string {
  return createHash("sha256")
    .update(`blueeconomy.ledger-commit.v1|${transferId.toString(16).padStart(32, "0")}|${entry.kind}|${entry.credentialId}|${entry.occurredAt}`, "utf8")
    .digest("hex");
}

export class TigerBeetleIssuanceLedger implements IssuanceLedger {
  private client: TigerBeetleClientLike | undefined;
  private readonly options: TigerBeetleLedgerOptions;

  public constructor(options: TigerBeetleLedgerOptions) {
    this.options = options;
    if (options.client !== undefined) this.client = options.client;
  }

  public async record(entry: LedgerEntry): Promise<LedgerCommit> {
    // Phase-7 OTel (OTEL_DESIGN.md §3 TigerBeetle row): TB core has no native
    // OTel, so coverage is a client-side span at every ledger op. No-op when
    // telemetry is disabled; the posting semantics are unchanged.
    return withSpan("tigerbeetle.record", {
      kind: SpanKind.CLIENT,
      attributes: {
        "db.system": "tigerbeetle",
        "ledger.entry.kind": entry.kind,
        "ledger.id": this.options.ledger,
      },
    }, (span) => this.recordEntry(entry, span));
  }

  private async recordEntry(entry: LedgerEntry, span: { setAttribute(key: string, value: string | number | boolean): void }): Promise<LedgerCommit> {
    if (entry.credentialId.trim() !== entry.credentialId || entry.credentialId.length === 0) {
      throw new Error("ledger entry credential id must be canonical non-empty text");
    }
    if (!Number.isFinite(Date.parse(entry.occurredAt))) {
      throw new Error("ledger entry occurredAt must be a valid date-time");
    }
    const client = await this.connection();
    const transferId = deterministicTransferId(entry);
    const accountId = credentialAccountId(entry.credentialId);
    const accountErrors = await client.createAccounts([{
      id: accountId,
      debits_pending: 0n, debits_posted: 0n, credits_pending: 0n, credits_posted: 0n,
      user_data_128: 0n, user_data_64: 0n, user_data_32: 0, reserved: 0,
      ledger: this.options.ledger, code: TB_CODE_ISSUANCE, flags: 0, timestamp: 0n,
    }]);
    for (const error of accountErrors) {
      if (error.result !== TB_STATUS_EXISTS) {
        throw new Error(`TigerBeetle account creation failed with status ${error.result}`);
      }
    }
    // Issuance debits the NIMASA clearing account into the credential's
    // account; revocation posts the counter-entry in the reverse direction so
    // the credential's ledger balance is reversed rather than doubled.
    const issuanceDirection = entry.kind === "issuance";
    const transfer = {
      id: transferId,
      debit_account_id: issuanceDirection ? NIMASA_CLEARING_ACCOUNT : accountId,
      credit_account_id: issuanceDirection ? accountId : NIMASA_CLEARING_ACCOUNT,
      amount: 1n,
      pending_id: 0n,
      user_data_128: 0n,
      user_data_64: 0n,
      user_data_32: 0,
      timeout: 0,
      ledger: this.options.ledger,
      code: entry.kind === "issuance" ? TB_CODE_ISSUANCE : TB_CODE_REVOCATION,
      flags: 0,
      timestamp: 0n,
    };
    const errors = await client.createTransfers([transfer]);
    let replayed = false;
    for (const error of errors) {
      if (error.result === TB_STATUS_EXISTS) {
        replayed = true;
      } else {
        throw new Error(`TigerBeetle transfer creation failed with status ${error.result}`);
      }
    }
    void TB_STATUS_CREATED;
    span.setAttribute("ledger.idempotent_replay", replayed);
    span.setAttribute("ledger.transfer_id", transferId.toString(16).padStart(32, "0"));
    return {
      transferIdHex: transferId.toString(16).padStart(32, "0"),
      commitHash: ledgerCommitHash(transferId, entry),
      idempotentReplay: replayed,
    };
  }

  public async healthCheck(): Promise<void> {
    const client = await this.connection();
    await client.createAccounts([]);
  }

  public async close(): Promise<void> {
    // tigerbeetle-node clients do not expose an explicit close handle.
  }

  private async connection(): Promise<TigerBeetleClientLike> {
    if (this.client !== undefined) return this.client;
    const tigerbeetle = await import("tigerbeetle-node");
    this.client = tigerbeetle.createClient({
      cluster_id: this.options.clusterId,
      replica_addresses: this.options.replicaAddresses,
    }) as unknown as TigerBeetleClientLike;
    return this.client;
  }
}

/** Fail-closed factory: production issuance requires a TigerBeetle cluster. */
export function createIssuanceLedgerFromEnv(env: NodeJS.ProcessEnv = process.env): IssuanceLedger {
  const addresses = env["BLUEECONOMY_TIGERBEETLE_ADDRESSES"];
  if (addresses === undefined || addresses.trim().length === 0) {
    throw new Error("issuance ledger is not configured: set BLUEECONOMY_TIGERBEETLE_ADDRESSES (fail-closed)");
  }
  const replicaAddresses = addresses.split(",").map((entry) => entry.trim()).filter((entry) => entry.length > 0);
  if (replicaAddresses.length === 0) {
    throw new Error("BLUEECONOMY_TIGERBEETLE_ADDRESSES must contain at least one replica address");
  }
  const clusterId = BigInt(env["BLUEECONOMY_TIGERBEETLE_CLUSTER_ID"] ?? "0");
  const ledger = Number.parseInt(env["BLUEECONOMY_TIGERBEETLE_LEDGER"] ?? String(TB_LEDGER_DEFAULT), 10);
  if (!Number.isInteger(ledger) || ledger <= 0) {
    throw new Error("BLUEECONOMY_TIGERBEETLE_LEDGER must be a positive integer");
  }
  return new TigerBeetleIssuanceLedger({ clusterId, replicaAddresses, ledger });
}
