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
