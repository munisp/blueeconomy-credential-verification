import assert from "node:assert/strict";
import test from "node:test";

import { serviceTracer } from "../src/telemetry/spans.js";
import { startTelemetry } from "../src/telemetry/telemetry.js";

/**
 * Collector-down behavior (OTEL_DESIGN.md §1 fail-open): export failures
 * drop spans with a metric, never a request/process failure. The drop
 * counter is exercised deterministically with a failing exporter injected
 * through the test seam; the unreachable-endpoint case proves boot and
 * shutdown stay non-blocking against a dead collector.
 */

async function settle(): Promise<void> {
  for (let i = 0; i < 5; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}

test("drop-with-metric: failed exports are counted, never thrown", async () => {
  const failingExporter = {
    export(_spans: unknown[], resultCallback: (result: { code: number }) => void): void {
      // ExportResultCode.FAILED === 1
      resultCallback({ code: 1 });
    },
    shutdown: () => Promise.resolve(),
  };
  const handle = await startTelemetry({
    env: { OTEL_EXPORTER_OTLP_ENDPOINT: "http://collector.invalid:4318" },
    spanExporter: failingExporter,
  });
  assert.equal(handle.enabled, true);

  const span = serviceTracer().startSpan("drop-test");
  span.end();
  await settle();

  assert.equal(handle.droppedSpanCount(), 1);
  assert.match(handle.metrics(), /telemetry_dropped_total 1/);
  await handle.shutdown();
});

test("unreachable collector: boot resolves enabled and shutdown never rejects", async () => {
  const handle = await startTelemetry({
    env: { OTEL_EXPORTER_OTLP_ENDPOINT: "http://127.0.0.1:9" },
  });
  assert.equal(handle.enabled, true);
  assert.equal(handle.reason, "ok");

  const span = serviceTracer().startSpan("unreachable-collector-test");
  span.end();

  const started = Date.now();
  await handle.shutdown(); // must resolve, with the 5 s ceiling
  assert.ok(Date.now() - started < 6_000, "shutdown must respect the flush ceiling");
});
