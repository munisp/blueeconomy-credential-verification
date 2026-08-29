import assert from "node:assert/strict";
import test from "node:test";

import {
  createIssuanceLedgerFromEnv,
  credentialAccountId,
  deterministicTransferId,
  ledgerCommitHash,
  TigerBeetleIssuanceLedger,
  type LedgerEntry,
  type TigerBeetleClientLike,
} from "../src/ledger/issuance-ledger.js";

const entry: LedgerEntry = {
  credentialId: "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  holderReference: "did:web:wallet.seafarer.example:ng-0001",
  issuer: "did:web:credentials.nimasa.gov.ng",
  kind: "issuance",
  occurredAt: "2026-06-01T00:00:00.000Z",
};

function fakeClient(transferResults: number[] = []): TigerBeetleClientLike & { transfers: unknown[] } {
  const transfers: unknown[] = [];
  return {
    transfers,
    async createAccounts() {
      return [];
    },
    async createTransfers(batch: unknown[]) {
      transfers.push(...batch);
      return transferResults.map((result, index) => ({ index, result }));
    },
  };
}

test("transfer ids are deterministic and within the 128-bit range", () => {
  const first = deterministicTransferId(entry);
  const second = deterministicTransferId({ ...entry });
  assert.equal(first, second);
  assert.ok(first > 0n && first < (1n << 128n));
  const other = deterministicTransferId({ ...entry, kind: "revocation" });
  assert.notEqual(first, other);
});

test("ledger commit hash is deterministic and binds the entry", () => {
  const transferId = deterministicTransferId(entry);
  const commit = ledgerCommitHash(transferId, entry);
  assert.match(commit, /^[0-9a-f]{64}$/);
  assert.equal(commit, ledgerCommitHash(transferId, { ...entry }));
  assert.notEqual(commit, ledgerCommitHash(transferId, { ...entry, occurredAt: "2026-06-02T00:00:00.000Z" }));
});

test("tigerbeetle ledger records the transfer and reports fresh commits", async () => {
  const client = fakeClient([]);
  const ledger = new TigerBeetleIssuanceLedger({ clusterId: 0n, replicaAddresses: ["3000"], ledger: 1, client });
  const commit = await ledger.record(entry);
  assert.equal(commit.idempotentReplay, false);
  assert.equal(client.transfers.length, 1);
  const transfer = client.transfers[0] as { id: bigint; amount: bigint; code: number };
  assert.equal(transfer.id, deterministicTransferId(entry));
  assert.equal(transfer.amount, 1n);
  assert.equal(transfer.code, 7101);
});

test("tigerbeetle 'exists' result is treated as an idempotent replay", async () => {
  const client = fakeClient([21]);
  const ledger = new TigerBeetleIssuanceLedger({ clusterId: 0n, replicaAddresses: ["3000"], ledger: 1, client });
  const commit = await ledger.record(entry);
  assert.equal(commit.idempotentReplay, true);
});

test("tigerbeetle errors fail closed", async () => {
  const client = fakeClient([36]);
  const ledger = new TigerBeetleIssuanceLedger({ clusterId: 0n, replicaAddresses: ["3000"], ledger: 1, client });
  await assert.rejects(() => ledger.record(entry), /transfer creation failed with status 36/);
});

test("ledger factory fails closed without a configured cluster", () => {
  assert.throws(() => createIssuanceLedgerFromEnv({}), /not configured.*fail-closed/);
  assert.throws(() => createIssuanceLedgerFromEnv({ BLUEECONOMY_TIGERBEETLE_ADDRESSES: "  " }), /not configured/);
  const ledger = createIssuanceLedgerFromEnv({ BLUEECONOMY_TIGERBEETLE_ADDRESSES: "127.0.0.1:3000,127.0.0.1:3001" });
  assert.ok(ledger instanceof TigerBeetleIssuanceLedger);
});

test("credential account ids are stable and non-zero", () => {
  const account = credentialAccountId(entry.credentialId);
  assert.equal(account, credentialAccountId(entry.credentialId));
  assert.ok(account > 0n);
});

test("CV-1: revocation posts the counter-entry in the reverse direction of issuance", async () => {
  const client = fakeClient([]);
  const ledger = new TigerBeetleIssuanceLedger({ clusterId: 0n, replicaAddresses: ["3000"], ledger: 1, client });
  const NIMASA_CLEARING = 7_100_000_001n;
  const account = credentialAccountId(entry.credentialId);

  await ledger.record(entry);
  await ledger.record({ ...entry, kind: "revocation", occurredAt: "2026-06-02T00:00:00.000Z" });
  assert.equal(client.transfers.length, 2);
  const [issuance, revocation] = client.transfers as [{
    debit_account_id: bigint;
    credit_account_id: bigint;
    code: number;
  }, {
    debit_account_id: bigint;
    credit_account_id: bigint;
    code: number;
  }];
  assert.equal(issuance.debit_account_id, NIMASA_CLEARING, "issuance debits the NIMASA clearing account");
  assert.equal(issuance.credit_account_id, account, "issuance credits the credential account");
  assert.equal(revocation.debit_account_id, account, "revocation reverses the direction: the credential account is debited back");
  assert.equal(revocation.credit_account_id, NIMASA_CLEARING, "revocation credits the NIMASA clearing account back");
  assert.equal(issuance.code, 7101);
  assert.equal(revocation.code, 7102, "revocation keeps its distinct transfer code");
});

test("CV-1: account ids carry 128 bits of entropy and never collide on an 8-byte prefix", () => {
  // Two credential ids that share their first 8 bytes (and any truncation of
  // the old 8-byte derivation's input space) must still map to distinct,
  // full-range 128-bit accounts.
  const left = credentialAccountId("urn:uuid:00000000-aaaa-0000-0000-000000000001");
  const right = credentialAccountId("urn:uuid:00000000-aaaa-0000-0000-000000000002");
  assert.notEqual(left, right);
  // Full 128-bit range: across many credentials the derivation must use the
  // upper 64 bits (the retired derivation never exceeded ~2^30).
  const seen = new Set<bigint>();
  let above64Bits = 0;
  for (let index = 0; index < 256; index += 1) {
    const account = credentialAccountId(`urn:uuid:00000000-0000-0000-0000-${String(index).padStart(12, "0")}`);
    assert.ok(account > 0n && account < (1n << 128n));
    if (account >= (1n << 64n)) above64Bits += 1;
    seen.add(account);
  }
  assert.equal(seen.size, 256, "no collisions across 256 credential ids");
  assert.ok(above64Bits > 0, "account ids must span the full 128-bit range");
  assert.ok(!seen.has(7_100_000_001n), "no credential maps onto the NIMASA clearing account");
});
