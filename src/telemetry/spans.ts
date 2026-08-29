import {
  context,
  propagation,
  SpanKind,
  SpanStatusCode,
  trace,
  type Attributes,
  type Context,
  type Span,
  type Tracer,
} from "@opentelemetry/api";

/**
 * Manual-span helpers shared by the HTTP edge, credential service, issuance
 * ledger and Kafka outbox (phase-7 OTel, OTEL_DESIGN.md §2 Node/TS row).
 *
 * Everything here rides on @opentelemetry/api ONLY: when the SDK is not
 * started (OTEL_EXPORTER_OTLP_ENDPOINT unset — the sanctioned fail-open)
 * every tracer/span is a no-op and the default propagator injects/extracts
 * nothing, so these helpers add no behaviour and no measurable cost. No
 * business logic lives here.
 */

export const SERVICE_NAME = "blueeconomy-credential-verification";

export function serviceTracer(): Tracer {
  return trace.getTracer(SERVICE_NAME);
}

export interface SpanOptions {
  kind?: SpanKind;
  attributes?: Attributes;
}

/**
 * Runs `fn` inside a new span (active in the async context so child spans
 * and header injection parent correctly). Errors are recorded on the span
 * and rethrown unchanged — telemetry never swallows or alters failures.
 */
export async function withSpan<T>(name: string, options: SpanOptions, fn: (span: Span) => Promise<T>): Promise<T> {
  const span = serviceTracer().startSpan(name, {
    kind: options.kind ?? SpanKind.INTERNAL,
    ...(options.attributes !== undefined ? { attributes: options.attributes } : {}),
  });
  try {
    return await context.with(trace.setSpan(context.active(), span), () => fn(span));
  } catch (error) {
    span.recordException(error instanceof Error ? error : new Error(String(error)));
    span.setStatus({ code: SpanStatusCode.ERROR });
    throw error;
  } finally {
    span.end();
  }
}

/** Runs `fn` with `ctx` as the active context (extracted inbound parent). */
export function withContext<T>(ctx: Context, fn: () => Promise<T>): Promise<T> {
  return context.with(ctx, fn);
}

const inboundHeaderGetter = {
  get(carrier: Record<string, string | string[] | undefined>, key: string): string | undefined {
    let value = carrier[key];
    if (Array.isArray(value)) value = value[0];
    // Node joins repeated headers with ", ". An upstream instrumented client
    // can append its own traceparent to the caller's; per W3C the first
    // traceparent is the caller's. (tracestate is comma-joined BY DESIGN and
    // must never be split.)
    if (key === "traceparent" && typeof value === "string" && value.includes(",")) {
      value = value.split(",")[0]?.trim();
    }
    return value;
  },
  keys(carrier: Record<string, string | string[] | undefined>): string[] {
    return Object.keys(carrier);
  },
};

/** Extracts a W3C traceparent parent context from inbound HTTP headers. */
export function extractInboundContext(headers: Record<string, string | string[] | undefined>): Context {
  return propagation.extract(context.active(), headers, inboundHeaderGetter);
}

/**
 * Injects the active span context as W3C traceparent headers into an
 * outbound carrier (Kafka message headers). No-op when telemetry is
 * disabled (default no-op propagator), so carriers stay byte-identical.
 */
export function injectTraceContext(carrier: Record<string, string>): void {
  propagation.inject(context.active(), carrier);
}
