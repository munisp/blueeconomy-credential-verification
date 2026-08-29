import assert from "node:assert/strict";
import test from "node:test";

import {
  createBitstring,
  decodeBitstring,
  encodeBitstring,
  getStatusBit,
  setStatusBit,
} from "../src/vc/status-list.js";

/**
 * CV-3: W3C Bitstring Status List conformance vectors. The specification is
 * MSB-first: bit i lives in byte floor(i / 8) at position 7 - (i % 8).
 * These vectors pin the byte-level layout so the bitstring is interoperable
 * with blueeconomy-tax-stamps, blueeconomy-mobile and any independent W3C
 * verifier.
 */

test("bit 0 is the most significant bit of the first byte (0x80)", () => {
  const bits = createBitstring();
  setStatusBit(bits, 0, true);
  assert.equal(bits[0], 0x80);
  assert.ok(bits.slice(1).every((byte) => byte === 0));
});

test("bit 7 is the least significant bit of the first byte (0x01)", () => {
  const bits = createBitstring();
  setStatusBit(bits, 7, true);
  assert.equal(bits[0], 0x01);
  assert.ok(bits.slice(1).every((byte) => byte === 0));
});

test("bit 8 is the most significant bit of the second byte", () => {
  const bits = createBitstring();
  setStatusBit(bits, 8, true);
  assert.equal(bits[0], 0x00);
  assert.equal(bits[1], 0x80);
  assert.ok(bits.slice(2).every((byte) => byte === 0));
});

test("getStatusBit reads back exactly the MSB-first positions that were set", () => {
  const bits = createBitstring();
  const indices = [0, 1, 7, 8, 9, 15, 16, 1023, 1_048_575];
  for (const index of indices) setStatusBit(bits, index, true);
  for (const index of indices) {
    assert.equal(getStatusBit(bits, index), true, `index ${index} must read back as set`);
  }
  // Neighbouring bits in the same bytes must remain clear.
  for (const index of [2, 6, 10, 14, 17, 1022, 1024, 1_048_574]) {
    assert.equal(getStatusBit(bits, index), false, `index ${index} must remain clear`);
  }
  setStatusBit(bits, 8, false);
  assert.equal(getStatusBit(bits, 8), false, "clearing a bit must not disturb its byte neighbours");
  assert.equal(getStatusBit(bits, 0), true);
  assert.equal(getStatusBit(bits, 9), true);
});

test("an MSB-first reference bitstring decodes to the specified indices", () => {
  // Hand-built reference buffer (as an external W3C verifier would publish):
  // byte 0 = 0b1000_0001 -> indices 0 and 7; byte 1 = 0b0100_0000 -> index 9.
  const bits = createBitstring();
  bits[0] = 0b1000_0001;
  bits[1] = 0b0100_0000;
  assert.equal(getStatusBit(bits, 0), true);
  assert.equal(getStatusBit(bits, 7), true);
  assert.equal(getStatusBit(bits, 9), true);
  assert.equal(getStatusBit(bits, 1), false);
  assert.equal(getStatusBit(bits, 8), false);
});

test("encode/decode round-trip preserves the MSB-first layout", () => {
  const bits = createBitstring();
  setStatusBit(bits, 0, true);
  setStatusBit(bits, 7, true);
  setStatusBit(bits, 8, true);
  const decoded = decodeBitstring(encodeBitstring(bits));
  assert.equal(decoded[0], 0x81);
  assert.equal(decoded[1], 0x80);
  assert.equal(getStatusBit(decoded, 0), true);
  assert.equal(getStatusBit(decoded, 7), true);
  assert.equal(getStatusBit(decoded, 8), true);
});
