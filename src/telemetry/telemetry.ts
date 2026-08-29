import type { ClientInterceptors } from "@temporalio/client";
import type { WorkerInterceptors } from "@temporalio/worker";
import { createRequire } from "node:module";

import { SERVICE_NAME } from "./spans.js";

/**
 * Server-side OTel bootstrap (phase-7, OTEL_DESIGN.md §1 + §2 Node/TS row).
 *
 * Fail-open contract (the one sanctioned fail-open): the SDK is GUARDED by
 * OTEL_EXPORTER_OTLP_ENDPOINT. Unset/empty = telemetry disabled, no OTel
 * packages are even loaded, boot and every request behave identically. When
 * set, export is batched and non-blocking; a dead collector drops spans with
 * a `telemetry_dropped_total` counter (surfaced on /metrics by main.ts) —
 * never a request failure. shutdown() flushes with a hard 5 s ceiling.
 *
 * Auto-instrumentation honesty note: this service is ESM ("type": "module").
 * sdk-node auto-instrumentations hook modules loaded AFTER sdk.start(); the
 * http/pg/kafkajs auto-instrumentations are enabled and hook what the
 * runtime allows, but full ESM auto-hooking additionally requires launching
 * with `--import @opentelemetry/auto-instrumentations-node/register`
 * (a deployment/gitops decision, not made here). The guaranteed coverage is
 * therefore the manual spans: HTTP dispatch (SERVER span + traceparent
 * extraction), PBAC evaluation child span, vc.issue / vc.verify / vc.revoke,
 * TigerBeetle ledger ops, Kafka outbox produce (with manual traceparent
 * carrier), and the Temporal worker/client interceptors.
 */

export interface TelemetryOptions {
  env?: NodeJS.ProcessEnv;
  /**
   * Test seam: inject a SpanExporter (e.g. InMemorySpanExporter) to inspect
   * finished spans. When provided, telemetry starts even without an endpoint.
   * Typed loosely so this module keeps zero static OTel SDK imports.
   */
  spanExporter?: unknown;
}

export interface TelemetryHandle {
  readonly enabled: boolean;
  /** Human-readable reason when disabled (or "ok" when enabled). */
  readonly reason: string;
  /** Spans dropped because export to the collector failed. */
  droppedSpanCount(): number;
  /** Prometheus text for the drop counter ("" when disabled). */
  metrics(): string;
  /** Flushes pending spans with a 5 s ceiling; never rejects. */
  shutdown(): Promise<void>;
}

const SHUTDOWN_TIMEOUT_MS = 5_000;

function disabledHandle(reason: string): TelemetryHandle {
  return {
    enabled: false,
    reason,
    droppedSpanCount: () => 0,
    metrics: () => "",
    shutdown: () => Promise.resolve(),
  };
}

export async function startTelemetry(options: TelemetryOptions = {}): Promise<TelemetryHandle> {
  const env = options.env ?? process.env;
  const endpoint = env["OTEL_EXPORTER_OTLP_ENDPOINT"]?.trim();
  if ((endpoint === undefined || endpoint.length === 0) && options.spanExporter === undefined) {
    return disabledHandle("OTEL_EXPORTER_OTLP_ENDPOINT is not set");
  }

  try {
    // Dynamic imports: zero OTel SDK footprint when telemetry is disabled.
    const [sdkNode, autoInst, otlpHttp, traceBase, resources, semconv, core] = await Promise.all([
      import("@opentelemetry/sdk-node"),
      import("@opentelemetry/auto-instrumentations-node"),
      import("@opentelemetry/exporter-trace-otlp-http"),
      import("@opentelemetry/sdk-trace-base"),
      import("@opentelemetry/resources"),
      import("@opentelemetry/semantic-conventions"),
      import("@opentelemetry/core"),
    ]);

    let dropped = 0;
    const inner =
      options.spanExporter !== undefined
        ? (options.spanExporter as InstanceType<typeof otlpHttp.OTLPTraceExporter>)
        : new otlpHttp.OTLPTraceExporter({ url: `${(endpoint ?? "").replace(/\/+$/, "")}/v1/traces` });
    // Drop-with-metric: count spans the collector could not receive. The
    // batch processor isolates export failures from the request path; this
    // wrapper only observes the outcome for the drop counter.
    const countingExporter = {
      export(spans: unknown[], resultCallback: (result: { code: number }) => void): void {
        (inner as { export: (s: unknown[], cb: (r: { code: number }) => void) => void }).export(spans, (result) => {
          if (result.code !== core.ExportResultCode.SUCCESS) dropped += spans.length;
          resultCallback(result);
        });
      },
      shutdown(): Promise<void> {
        return (inner as { shutdown: () => Promise<void> }).shutdown();
      },
    };

    const serviceName = env["OTEL_SERVICE_NAME"]?.trim() || SERVICE_NAME;
    // Injected (test) exporters flush synchronously for determinism;
    // production export is batched/async so telemetry never blocks requests.
    const exportingProcessor =
      options.spanExporter !== undefined
        ? new traceBase.SimpleSpanProcessor(countingExporter)
        : new traceBase.BatchSpanProcessor(countingExporter);
    const sdk = new sdkNode.NodeSDK({
      // Explicit resource only: auto-detection is async and would delay
      // global provider registration past boot (spans lost in the interim).
      autoDetectResources: false,
      resource: resources.resourceFromAttributes({ [semconv.ATTR_SERVICE_NAME]: serviceName }),
      spanProcessors: [exportingProcessor],
      instrumentations: [
        // http, pg and kafkajs auto-instrumentations are included here; fs is
        // disabled (high volume, no diagnostic value for this service).
        autoInst.getNodeAutoInstrumentations({
          "@opentelemetry/instrumentation-fs": { enabled: false },
        }),
      ],
    });
    sdk.start();

    return {
      enabled: true,
      reason: "ok",
      droppedSpanCount: () => dropped,
      metrics: () => `telemetry_dropped_total ${dropped}\n`,
      shutdown: async () => {
        try {
          await Promise.race([
            sdk.shutdown(),
            new Promise<void>((resolve) => setTimeout(resolve, SHUTDOWN_TIMEOUT_MS)),
          ]);
        } catch {
          // fail-open: telemetry shutdown must never break process exit
        }
      },
    };
  } catch {
    return disabledHandle("telemetry initialisation failed");
  }
}

/**
 * Temporal worker OTel interceptors (workflow + activity spans join the
 * service traces). Only loaded when telemetry is enabled; returns undefined
 * (never throws) if the interceptor package cannot load — the worker then
 * runs without telemetry rather than failing closed on an observability dep.
 */
export async function temporalWorkerInterceptors(): Promise<WorkerInterceptors | undefined> {
  try {
    const { OpenTelemetryActivityInboundInterceptor } = await import("@temporalio/interceptors-opentelemetry");
    const require = createRequire(import.meta.url);
    return {
      activityInbound: [(ctx) => new OpenTelemetryActivityInboundInterceptor(ctx)],
      workflowModules: [require.resolve("@temporalio/interceptors-opentelemetry/lib/workflow")],
    };
  } catch {
    return undefined;
  }
}

/** Temporal client OTel interceptor (query/start/signal spans). */
export async function temporalClientInterceptors(): Promise<ClientInterceptors | undefined> {
  try {
    const { OpenTelemetryWorkflowClientInterceptor } = await import("@temporalio/interceptors-opentelemetry");
    return { workflow: [new OpenTelemetryWorkflowClientInterceptor()] };
  } catch {
    return undefined;
  }
}
