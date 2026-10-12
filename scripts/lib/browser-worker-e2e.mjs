import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { writeFile, readFile } from "node:fs/promises";
import { chromium } from "playwright-core";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { waitForBrowserDevtoolsPort } from "../../dist/browser/BrowserProcessStartup.js";
import {
  startRuntimeFixtureBrowser,
  closeRuntimeFixtureResources,
} from "./browser-runtime-fixture-lifecycle.mjs";
import { startWorkerSite } from "../fixtures/browser-worker-site.mjs";
import { parseEvidence } from "../../dist/domain/evidence.js";
import { webPageInspectionSchema } from "../../dist/domain/browserObservationSchemas.js";
import { mcpTextValue } from "./mcp-verifier-results.mjs";

/** Real workers, selected-origin negatives, source digests, cache delivery and owned cleanup through public adapters. */
export async function verifyBrowserWorkers(
  executable,
  entrypoint = fileURLToPath(new URL("../rea.mjs", import.meta.url)),
) {
  const site = await startWorkerSite();
  let fixture, browser, client, transport, primaryError, foreignSite;
  try {
    fixture = await startRuntimeFixtureBrowser(executable, site.origin);
    let stderr = "";
    fixture.browser.stderr.on("data", (c) => {
      if (stderr.length < 65536) stderr += c;
    });
    const port = await waitForBrowserDevtoolsPort({
      child: fixture.browser,
      executable,
      activePortPath: join(fixture.profile, "DevToolsActivePort"),
      stderr: () => stderr,
      timeoutMs: 20000,
    });
    const endpoint = `http://127.0.0.1:${port}`;
    browser = await chromium.connectOverCDP(endpoint);
    const context = browser.contexts()[0];
    const page = context.pages()[0];
    await page.evaluate(() => window.ready);
    const other = await context.newPage();
    await other.goto(site.origin + "/other");
    await other.evaluate(() => window.ready);
    foreignSite = await startWorkerSite();
    const foreign = await context.newPage();
    await foreign.goto(foreignSite.origin);
    await foreign.evaluate(() => window.ready);
    const cdp = await context.newCDPSession(page);
    const target = (await cdp.send("Target.getTargetInfo")).targetInfo.targetId;
    const targets = (await cdp.send("Target.getTargets")).targetInfos;
    const shared = targets.find(
      (t) => t.type === "shared_worker" && t.url.startsWith(site.origin + "/"),
    );
    const foreignWorker = targets.find(
      (t) => t.type === "worker" && t.url.startsWith(foreignSite.origin + "/"),
    );
    assert.ok(shared);
    assert.ok(foreignWorker);
    const input = {
      cdp_endpoint: endpoint,
      target_id: target,
      observation_ms: 2000,
      include_script_sources: true,
    };
    const cli = await promisify(execFile)(
      process.execPath,
      [
        entrypoint,
        "inspect-web-page",
        endpoint,
        target,
        "--include-script-sources",
        "--observation-ms",
        "100",
        "--json",
      ],
      { timeout: 40000, maxBuffer: 32 * 1024 * 1024 },
    );
    const cliResult = webPageInspectionSchema.parse(
      parseEvidence(JSON.parse(cli.stdout)).normalized_result,
    );
    const summarize = (result) =>
      result.workers
        .map((w) => ({
          type: w.type,
          ownership: w.observation.ownership,
          sources: w.observation.scripts.map((s) =>
            s.source.included ? s.source.artifact.sha256 : null,
          ),
        }))
        .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
    check(cliResult, site, target, false);
    const explicitCli = await promisify(execFile)(
      process.execPath,
      [
        entrypoint,
        "inspect-web-page",
        endpoint,
        target,
        "--include-script-sources",
        "--worker-target-ids",
        shared.targetId,
        "--observation-ms",
        "0",
        "--json",
      ],
      { timeout: 40000, maxBuffer: 32 * 1024 * 1024 },
    );
    check(
      webPageInspectionSchema.parse(
        parseEvidence(JSON.parse(explicitCli.stdout)).normalized_result,
      ),
      site,
      target,
      true,
    );
    transport = new StdioClientTransport({
      command: process.execPath,
      args: [entrypoint, "mcp"],
      stderr: "pipe",
      env: { ...process.env, REA_LOG_LEVEL: "silent" },
    });
    client = new Client({ name: "worker-verifier", version: "1" });
    await client.connect(transport);
    const rejected = await client.callTool({
      name: "inspect_web_page",
      arguments: { ...input, worker_target_ids: [foreignWorker.targetId] },
    });
    assert.equal(rejected.isError, true);
    assert.match(mcpTextValue(rejected), /target_not_allowed/);
    const capture = async (arguments_, act) => {
      let action;
      const response = await client.callTool(
        { name: "inspect_web_page", arguments: arguments_ },
        {
          timeout: 40000,
          onprogress: (n) => {
            if (
              action === undefined &&
              n.message?.includes("Observing page events")
            ) {
              action = act?.() ?? Promise.resolve();
              void action.catch(() => undefined);
            }
          },
        },
      );
      assert.ok(action, "missing observation progress");
      await action;
      assert.notEqual(response.isError, true, JSON.stringify(response));
      assert.deepEqual(
        JSON.parse(mcpTextValue(response)),
        response.structuredContent,
      );
      return webPageInspectionSchema.parse(
        parseEvidence(response.structuredContent).normalized_result,
      );
    };
    const defaultResult = await capture(input);
    check(defaultResult, site, target, false);
    assert.deepEqual(summarize(defaultResult), summarize(cliResult));
    const explicit = await capture(
      { ...input, worker_target_ids: [shared.targetId] },
      () => page.evaluate(() => window.act()),
    );
    check(explicit, site, target, true);
    const savedCapture = join(fixture.profile, "worker-capture.json");
    await writeFile(savedCapture, JSON.stringify(explicit));
    const exported = await promisify(execFile)(
      process.execPath,
      [
        entrypoint,
        "export-web-scripts",
        savedCapture,
        join(fixture.profile, "exported"),
        "--json",
      ],
      { timeout: 40000, maxBuffer: 32 * 1024 * 1024 },
    );
    const exportedResult = parseEvidence(
      JSON.parse(exported.stdout),
    ).normalized_result;
    const manifest = JSON.parse(
      await readFile(
        join(fixture.profile, "exported", "manifest.json"),
        "utf8",
      ),
    );
    const exportedWorkers = manifest.scripts.filter(
      (s) => s.source.kind === "worker-script",
    );
    assert.equal(exportedWorkers.length, 4);
    for (const script of exportedWorkers) {
      const bytes = await readFile(
        join(
          exportedResult.analysis_input.input_path,
          script.content.relative_path,
        ),
      );
      assert.equal(
        createHash("sha256").update(bytes).digest("hex"),
        script.content.sha256,
      );
    }
    assert.ok(
      explicit.workers
        .find((w) => w.type === "shared_worker")
        .observation.network_requests.some((r) =>
          r.url.endsWith("/shared-request"),
        ),
    );
    assert.ok(
      explicit.workers.some((w) =>
        w.observation.network_requests.some((r) =>
          r.url.endsWith("/worker-request"),
        ),
      ),
    );
    assert.ok(
      explicit.network.requests.some(
        (r) =>
          r.url.endsWith("/cached") &&
          r.response_source?.service_worker === true &&
          r.response_source?.service_worker_response_source === "cache-storage",
      ),
    );
    const terminated = await capture(input, () =>
      page.evaluate(() => window.worker.terminate()),
    );
    assert.ok(
      terminated.workers.some((w) =>
        w.observation.lifecycle.some((e) => e.event === "detached"),
      ),
    );
    const restarted = await capture(input, () =>
      page.evaluate(async () => {
        window.worker = new Worker("/worker.js");
        await new Promise((r) => (window.worker.onmessage = r));
      }),
    );
    assert.ok(
      restarted.workers.some(
        (w) =>
          w.observation.ownership === "page_related" &&
          w.observation.lifecycle.some((e) => e.event === "attached") &&
          w.observation.scripts.some(
            (s) => s.url.endsWith("/worker.js") && s.source.included,
          ),
      ),
    );
    const abort = new AbortController();
    let cancelled = false;
    try {
      await client.callTool(
        {
          name: "inspect_web_page",
          arguments: { ...input, observation_ms: 30000 },
        },
        {
          timeout: 40000,
          signal: abort.signal,
          onprogress: (n) => {
            if (n.message?.includes("Observing page events")) abort.abort();
          },
        },
      );
    } catch {
      cancelled = abort.signal.aborted;
    }
    assert.equal(cancelled, true);
    await client.ping();
    await capture({ ...input, observation_ms: 0 });
    assert.equal(page.isClosed(), false);
    assert.equal(other.isClosed(), false);
    await cdp.detach();
    return {
      cases: 9,
      originBoundary: true,
      exportedWorkerSources: exportedWorkers.length,
      browser: browser.version(),
      workerTypes: ["worker", "shared_worker", "service_worker"],
      sourceDigests: true,
      cliMcpParity: true,
      networkAndServiceWorkerResponse: true,
      cancellationRecovery: true,
    };
  } catch (cause) {
    primaryError = cause;
    throw cause;
  } finally {
    await closeRuntimeFixtureResources(
      [
        () => client?.close(),
        () => transport?.close(),
        () => browser?.close(),
        () => fixture?.close(),
        () => site.close(),
        () => foreignSite?.close(),
      ],
      primaryError,
    );
  }
}
function check(result, site, target, explicit) {
  const workers = result.workers;
  const related = workers.filter(
    (w) => w.observation.ownership === "page_related",
  );
  assert.equal(related.length, 2);
  assert.ok(
    workers.some(
      (w) =>
        w.type === "worker" &&
        w.observation.ownership === "unknown" &&
        w.observation.scripts.length === 0,
    ),
  );
  assert.ok(
    workers.some(
      (w) =>
        w.type === "service_worker" &&
        w.observation.ownership === "service_worker_client",
    ),
  );
  const shared = workers.find((w) => w.type === "shared_worker");
  assert.equal(shared.observation.ownership, "unknown");
  assert.equal(shared.observation.selected_explicitly, explicit);
  for (const worker of workers) {
    assert.equal(worker.origin, site.origin);
    if (worker.observation.ownership !== "unknown")
      assert.equal(worker.observation.page_target_id, target);
    for (const script of worker.observation.scripts) {
      assert.equal(script.source.included, true);
      const expected = site.sources[new URL(script.url).pathname];
      assert.equal(script.source.artifact.text, expected);
      assert.equal(
        script.source.artifact.sha256,
        createHash("sha256").update(expected).digest("hex"),
      );
    }
  }
  assert.equal(shared.observation.scripts.length, explicit ? 1 : 0);
  assert.ok(
    related.every(
      (w) =>
        w.observation.execution_contexts.length > 0 &&
        w.observation.scripts.length > 0,
    ),
  );
}
