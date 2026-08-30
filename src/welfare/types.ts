import { createHash } from "node:crypto";

/**
 * Crew Welfare / MLC 2006 domain vocabulary (phase 8). Mirrors the fail-closed
 * enums of blueeconomy-contracts proto/blueeconomy/contracts/v1/welfare.proto:
 * every value is an explicit member of a closed set — the proto UNSPECIFIED
 * zero values have no representation here, so an unspecified value can never
 * be constructed, stored or emitted.
 *
 * Anchors: MLC 2006 Reg 5.1.5 (on-board complaints), Reg 5.2.2 (flag-state
 * onshore channel), Reg 2.3 (hours of work/rest), Reg 4.4 (shore welfare).
 */

export const COMPLAINT_CHANNELS = ["onboard_r515", "flagstate_r522"] as const;
export type ComplaintChannel = (typeof COMPLAINT_CHANNELS)[number];

export const COMPLAINT_CATEGORIES = [
  "wages",
  "rest_hours",
  "accommodation",
  "food",
  "medical",
  "harassment_bullying",
  "repatriation",
  "abandonment",
  "other_mlc",
] as const;
export type ComplaintCategory = (typeof COMPLAINT_CATEGORIES)[number];

export const COMPLAINT_STATUSES = [
  "RECEIVED",
  "ACKED",
  "ONBOARD_PROCESS",
  "ESCALATED_FLAGSTATE",
  "REFERRED",
  "RESOLVED",
  "CLOSED",
] as const;
export type ComplaintStatus = (typeof COMPLAINT_STATUSES)[number];

/**
 * Governed lifecycle per the proto contract: RECEIVED -> ACKED ->
 * ONBOARD_PROCESS, with ESCALATED_FLAGSTATE and REFERRED as governed branches
 * and RESOLVED/CLOSED terminal. On-board complaints (Reg 5.1.5) may escalate
 * to the flag-state channel (Reg 5.2.2) when unresolved on board.
 */
export const COMPLAINT_TRANSITIONS: Readonly<Record<ComplaintStatus, readonly ComplaintStatus[]>> = {
  RECEIVED: ["ACKED"],
  ACKED: ["ONBOARD_PROCESS", "ESCALATED_FLAGSTATE"],
  ONBOARD_PROCESS: ["ESCALATED_FLAGSTATE", "REFERRED", "RESOLVED"],
  ESCALATED_FLAGSTATE: ["REFERRED", "RESOLVED"],
  REFERRED: ["RESOLVED"],
  RESOLVED: ["CLOSED"],
  CLOSED: [],
};

export function isLegalComplaintTransition(from: ComplaintStatus, to: ComplaintStatus): boolean {
  return COMPLAINT_TRANSITIONS[from].includes(to);
}

export const REFERRAL_STATUSES = ["OFFERED", "ACCEPTED", "ENGAGED", "CLOSED"] as const;
export type ReferralStatus = (typeof REFERRAL_STATUSES)[number];

/** OFFERED -> ACCEPTED -> ENGAGED -> CLOSED; OFFERED -> CLOSED is a decline. */
export const REFERRAL_TRANSITIONS: Readonly<Record<ReferralStatus, readonly ReferralStatus[]>> = {
  OFFERED: ["ACCEPTED", "CLOSED"],
  ACCEPTED: ["ENGAGED", "CLOSED"],
  ENGAGED: ["CLOSED"],
  CLOSED: [],
};

export function isLegalReferralTransition(from: ReferralStatus, to: ReferralStatus): boolean {
  return REFERRAL_TRANSITIONS[from].includes(to);
}

export const REST_HOUR_REGIMES = ["min_rest", "max_work"] as const;
export type RestHourRegime = (typeof REST_HOUR_REGIMES)[number];

export const REST_HOUR_RULES = [
  "min_rest_10h_24",
  "min_rest_77h_7d",
  "max_two_periods",
  "min_one_period_6h",
  "max_gap_14h",
  "max_work_14h_24",
  "max_work_72h_7d",
] as const;
export type RestHourRule = (typeof REST_HOUR_RULES)[number];

/** Rules evaluated under each Reg 2.3 regime; the regime itself is config. */
export const REGIME_RULES: Readonly<Record<RestHourRegime, readonly RestHourRule[]>> = {
  min_rest: ["min_rest_10h_24", "min_rest_77h_7d", "max_two_periods", "min_one_period_6h", "max_gap_14h"],
  max_work: ["max_work_14h_24", "max_work_72h_7d", "max_two_periods", "min_one_period_6h", "max_gap_14h"],
};

export const PROVIDER_KINDS = ["seafarer_centre", "medical", "transport", "comms", "faith", "helpline", "legal"] as const;
export type ProviderKind = (typeof PROVIDER_KINDS)[number];

/** Maps internal vocabulary to the proto enum suffix carried on the wire. */
export const PROTO_NAMES = {
  channel: { onboard_r515: "ONBOARD_R515", flagstate_r522: "FLAGSTATE_R522" } as const,
  category: {
    wages: "WAGES",
    rest_hours: "REST_HOURS",
    accommodation: "ACCOMMODATION",
    food: "FOOD",
    medical: "MEDICAL",
    harassment_bullying: "HARASSMENT_BULLYING",
    repatriation: "REPATRIATION",
    abandonment: "ABANDONMENT",
    other_mlc: "OTHER_MLC",
  } as const,
  regime: { min_rest: "MIN_REST", max_work: "MAX_WORK" } as const,
  rule: {
    min_rest_10h_24: "MIN_REST_10H_24",
    min_rest_77h_7d: "MIN_REST_77H_7D",
    max_two_periods: "MAX_TWO_PERIODS",
    min_one_period_6h: "MIN_ONE_PERIOD_6H",
    max_gap_14h: "MAX_GAP_14H",
    max_work_14h_24: "MAX_WORK_14H_24",
    max_work_72h_7d: "MAX_WORK_72H_7D",
  } as const,
};

/**
 * Tokenized reference for event payloads (welfare.proto: events carry a
 * tokenized reference only, never a name or credential payload). Deterministic
 * so consumers can correlate events for the same entity; resolvable only
 * inside the producing boundary (the welfare database holds the mapping).
 */
export function tokenizeReference(kind: "sfr" | "vsl" | "opr" | "svc", value: string): string {
  const digest = createHash("sha256").update(`blueeconomy.welfare.ref.v1|${kind}|${value}`, "utf8").digest("hex");
  return `${kind}-${digest.slice(0, 12)}`;
}

export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

/** Deterministic urn:uuid derived from a scoped key (idempotent retries). */
export function deterministicUuid(scope: string, key: string): string {
  const digest = createHash("sha256").update(`blueeconomy.welfare.v1|${scope}|${key}`, "utf8").digest("hex");
  return `urn:uuid:${digest.slice(0, 8)}-${digest.slice(8, 12)}-${digest.slice(12, 16)}-${digest.slice(16, 20)}-${digest.slice(20, 32)}`;
}

export function isMember<T extends string>(values: readonly T[], value: unknown): value is T {
  return typeof value === "string" && (values as readonly string[]).includes(value);
}
