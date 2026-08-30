import { REGIME_RULES, type RestHourRegime, type RestHourRule } from "./types.js";

/**
 * MLC 2006 Reg 2.3 work/rest rule engine. Pure and deterministic: the same
 * (periods, regime) always yields the same flags, which is what makes the
 * persisted rest_hour_flag rows recomputable under a policy_version.
 *
 * Semantics (per the flag-adopted standard selected by the signed welfare
 * policy — never hard-coded which regime applies):
 *   - min_rest: >= 10 h rest in ANY 24 h window and >= 77 h in ANY 7 d window;
 *   - max_work: <= 14 h work in ANY 24 h window and <= 72 h in ANY 7 d window;
 *   - structural (both regimes): rest in any 24 h window is divided into no
 *     more than 2 periods, at least one period is >= 6 h, and the interval
 *     between consecutive rest periods is <= 14 h.
 *
 * "Any 24 h / 7 d" windows are evaluated exactly: window start candidates are
 * the period boundaries (and boundaries shifted by the window length), because
 * the rest/work sum of a fixed-length window is piecewise linear with slope
 * changes only at those points — the extremum over all windows is therefore
 * attained at a candidate. Boundary values are compliant: exactly 10 h rest,
 * exactly 6 h, exactly 14 h gap, exactly 14 h work do not flag.
 */

export interface RestHourPeriod {
  /** ISO 8601 date-times; end must be after start. */
  start: string;
  end: string;
  kind: "work" | "rest";
}

export interface RuleBreach {
  rule: RestHourRule;
  /** Operational detail only: durations and window boundaries, never PII. */
  detail: string;
}

export class RestRecordValidationError extends Error {}

const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;
const WEEK_MS = 7 * DAY_MS;

interface Interval {
  startMs: number;
  endMs: number;
  kind: "work" | "rest";
}

/** Parses and validates fail-closed: canonical ISO, start < end, no overlaps. */
export function parsePeriods(periods: readonly RestHourPeriod[]): Interval[] {
  if (periods.length === 0 || periods.length > 64) {
    throw new RestRecordValidationError("periods must contain 1-64 entries");
  }
  const intervals = periods.map((period, index) => {
    if (period.kind !== "work" && period.kind !== "rest") {
      throw new RestRecordValidationError(`period ${index} kind must be work or rest`);
    }
    const startMs = Date.parse(period.start);
    const endMs = Date.parse(period.end);
    if (!Number.isFinite(startMs) || !Number.isFinite(endMs)) {
      throw new RestRecordValidationError(`period ${index} must carry valid ISO date-times`);
    }
    if (endMs <= startMs) {
      throw new RestRecordValidationError(`period ${index} end must be after start`);
    }
    return { startMs, endMs, kind: period.kind };
  });
  intervals.sort((left, right) => left.startMs - right.startMs || left.endMs - right.endMs);
  for (let index = 1; index < intervals.length; index += 1) {
    if (intervals[index]!.startMs < intervals[index - 1]!.endMs) {
      throw new RestRecordValidationError("periods must not overlap; a submitted record is one truthful timeline");
    }
  }
  const spanMs = intervals[intervals.length - 1]!.endMs - intervals[0]!.startMs;
  if (spanMs > 8 * DAY_MS) {
    throw new RestRecordValidationError("a daily record's periods must span at most 8 days");
  }
  return intervals;
}

/** Evaluates the regime's rule set against one submitted record. */
export function evaluateRestHours(periods: readonly RestHourPeriod[], regime: RestHourRegime): RuleBreach[] {
  const intervals = parsePeriods(periods);
  const breaches: RuleBreach[] = [];
  for (const rule of REGIME_RULES[regime]) {
    const breach = evaluateRule(rule, intervals);
    if (breach !== undefined) breaches.push(breach);
  }
  return breaches;
}

function evaluateRule(rule: RestHourRule, intervals: readonly Interval[]): RuleBreach | undefined {
  switch (rule) {
    case "min_rest_10h_24":
      return minimumWindowRule(rule, intervals, "rest", DAY_MS, 10 * HOUR_MS, "24 h");
    case "min_rest_77h_7d":
      return minimumWindowRule(rule, intervals, "rest", WEEK_MS, 77 * HOUR_MS, "7 d");
    case "max_work_14h_24":
      return maximumWindowRule(rule, intervals, "work", DAY_MS, 14 * HOUR_MS, "24 h");
    case "max_work_72h_7d":
      return maximumWindowRule(rule, intervals, "work", WEEK_MS, 72 * HOUR_MS, "7 d");
    case "max_two_periods":
      return maxTwoPeriodsRule(intervals);
    case "min_one_period_6h":
      return minOnePeriod6hRule(intervals);
    case "max_gap_14h":
      return maxGap14hRule(intervals);
  }
}

/**
 * Window-start candidates: period boundaries and boundaries shifted by -L,
 * clipped to the recorded timeline. Windows are evaluated only where the
 * record carries data: a fixed-length window is placed so that it stays
 * within [spanStart, spanEnd]; when the record is shorter than the window
 * (a daily record assessed against a 7 d rule), the whole span is the single
 * assessed window. Evaluating windows outside the record would count
 * unrecorded time as zero rest/work and flag every conceivable record.
 */
function windowAnchors(intervals: readonly Interval[], windowMs: number): number[] {
  const spanStart = intervals[0]!.startMs;
  const spanEnd = intervals[intervals.length - 1]!.endMs;
  const latestStart = spanEnd - windowMs;
  if (latestStart <= spanStart) return [spanStart];
  const anchors = new Set<number>([spanStart, latestStart]);
  for (const interval of intervals) {
    for (const candidate of [interval.startMs, interval.endMs, interval.startMs - windowMs, interval.endMs - windowMs]) {
      if (candidate >= spanStart && candidate <= latestStart) anchors.add(candidate);
    }
  }
  return [...anchors].sort((left, right) => left - right);
}

/** Effective window length: the window, or the whole record span when shorter. */
function effectiveWindowMs(intervals: readonly Interval[], windowMs: number): number {
  const spanMs = intervals[intervals.length - 1]!.endMs - intervals[0]!.startMs;
  return Math.min(windowMs, spanMs);
}

function windowTotalMs(intervals: readonly Interval[], kind: "work" | "rest", startMs: number, windowMs: number): number {
  const endMs = startMs + windowMs;
  let total = 0;
  for (const interval of intervals) {
    if (interval.kind !== kind) continue;
    const overlap = Math.min(interval.endMs, endMs) - Math.max(interval.startMs, startMs);
    if (overlap > 0) total += overlap;
  }
  return total;
}

function minimumWindowRule(
  rule: RestHourRule,
  intervals: readonly Interval[],
  kind: "work" | "rest",
  windowMs: number,
  thresholdMs: number,
  windowLabel: string,
): RuleBreach | undefined {
  const effectiveMs = effectiveWindowMs(intervals, windowMs);
  let minimum = Number.POSITIVE_INFINITY;
  let minimumStart = 0;
  for (const anchor of windowAnchors(intervals, windowMs)) {
    const total = windowTotalMs(intervals, kind, anchor, effectiveMs);
    if (total < minimum) {
      minimum = total;
      minimumStart = anchor;
    }
  }
  if (minimum >= thresholdMs) return undefined;
  return {
    rule,
    detail: `${kind} totals ${formatMs(minimum)} in the ${windowLabel} window starting ${iso(minimumStart)}, below the ${formatMs(thresholdMs)} minimum`,
  };
}

function maximumWindowRule(
  rule: RestHourRule,
  intervals: readonly Interval[],
  kind: "work" | "rest",
  windowMs: number,
  thresholdMs: number,
  windowLabel: string,
): RuleBreach | undefined {
  const effectiveMs = effectiveWindowMs(intervals, windowMs);
  let maximum = Number.NEGATIVE_INFINITY;
  let maximumStart = 0;
  for (const anchor of windowAnchors(intervals, windowMs)) {
    const total = windowTotalMs(intervals, kind, anchor, effectiveMs);
    if (total > maximum) {
      maximum = total;
      maximumStart = anchor;
    }
  }
  if (maximum <= thresholdMs) return undefined;
  return {
    rule,
    detail: `${kind} totals ${formatMs(maximum)} in the ${windowLabel} window starting ${iso(maximumStart)}, above the ${formatMs(thresholdMs)} maximum`,
  };
}

/** Rest may be divided into no more than two periods in any 24 h window. */
function maxTwoPeriodsRule(intervals: readonly Interval[]): RuleBreach | undefined {
  const rest = intervals.filter((interval) => interval.kind === "rest");
  const effectiveMs = effectiveWindowMs(intervals, DAY_MS);
  let worst = 0;
  let worstStart = 0;
  for (const anchor of windowAnchors(intervals, DAY_MS)) {
    const count = rest.filter((interval) => interval.startMs >= anchor && interval.startMs < anchor + effectiveMs).length;
    if (count > worst) {
      worst = count;
      worstStart = anchor;
    }
  }
  if (worst <= 2) return undefined;
  return {
    rule: "max_two_periods",
    detail: `rest is divided into ${worst} periods in the 24 h window starting ${iso(worstStart)}, above the 2-period maximum`,
  };
}

/** In any 24 h window containing rest, at least one rest period must be >= 6 h. */
function minOnePeriod6hRule(intervals: readonly Interval[]): RuleBreach | undefined {
  const rest = intervals.filter((interval) => interval.kind === "rest");
  const effectiveMs = effectiveWindowMs(intervals, DAY_MS);
  let worstLongest = Number.POSITIVE_INFINITY;
  let worstStart = 0;
  for (const anchor of windowAnchors(intervals, DAY_MS)) {
    const endMs = anchor + effectiveMs;
    let longest = 0;
    let any = false;
    for (const interval of rest) {
      const overlap = Math.min(interval.endMs, endMs) - Math.max(interval.startMs, anchor);
      if (overlap > 0) {
        any = true;
        if (overlap > longest) longest = overlap;
      }
    }
    if (any && longest < worstLongest) {
      worstLongest = longest;
      worstStart = anchor;
    }
  }
  if (worstLongest >= 6 * HOUR_MS || worstLongest === Number.POSITIVE_INFINITY) return undefined;
  return {
    rule: "min_one_period_6h",
    detail: `the longest rest period in the 24 h window starting ${iso(worstStart)} is ${formatMs(worstLongest)}, below the 6h 0m single-period minimum`,
  };
}

/** The interval between consecutive rest periods must not exceed 14 h. */
function maxGap14hRule(intervals: readonly Interval[]): RuleBreach | undefined {
  const rest = intervals.filter((interval) => interval.kind === "rest");
  for (let index = 1; index < rest.length; index += 1) {
    const gap = rest[index]!.startMs - rest[index - 1]!.endMs;
    if (gap > 14 * HOUR_MS) {
      return {
        rule: "max_gap_14h",
        detail: `the interval between consecutive rest periods ending ${iso(rest[index - 1]!.endMs)} and starting ${iso(rest[index]!.startMs)} is ${formatMs(gap)}, above the 14h 0m maximum`,
      };
    }
  }
  return undefined;
}

function formatMs(ms: number): string {
  const totalMinutes = Math.round(ms / 60_000);
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  return `${hours}h ${minutes}m`;
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}
