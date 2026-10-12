import { expect, it, onTestFinished, vi } from "vitest";
import { CdpBrowserProvider } from "../../../src/browser/CdpBrowserProvider.js";
import { inspectWebPageInputSchema } from "../../../src/domain/browserObservation.js";
import {
  startFakeCdpBrowser,
  type FakeOptions,
} from "../../fixtures/fakeCdpBrowser.js";

const source = 'postMessage("worker 🧪");';

it("rejects a script identity change while its source read is pending", async () => {
  const { provider, input, browser } = await fixture({
    eventsBeforeReply: ["Debugger.getScriptSource"],
    commandEvents: (c, origin) =>
      c.method === "Debugger.getScriptSource" && c.sessionId === "worker-own"
        ? [
            {
              method: "Debugger.scriptParsed",
              sessionId: "worker-own",
              params: {
                scriptId: "1",
                url: origin + "/replacement.js",
                hash: "replacement",
                executionContextId: 1,
              },
            },
          ]
        : undefined,
  });
  expect(
    await provider.inspectPage({ ...input, observation_ms: 30_000 }),
  ).toMatchObject({ ok: false, error: { reason: "target_changed" } });
  await vi.waitFor(() => expect(browser.activeConnectionCount()).toBe(0));
});
async function fixture(extra: FakeOptions = {}) {
  const browser = await startFakeCdpBrowser({
    ...extra,
    commandResult(command, origin, reads) {
      const custom = extra.commandResult?.(command, origin, reads);
      if (custom !== undefined) return custom;
      if (
        command.method === "ServiceWorker.enable" ||
        command.method === "ServiceWorker.disable" ||
        command.method === "Target.setAutoAttach"
      )
        return {};
      if (command.method === "Target.getTargets")
        return {
          targetInfos: [
            {
              targetId: "own",
              type: "worker",
              url: origin + "/same.js",
              attached: false,
            },
            {
              targetId: "other",
              type: "worker",
              url: origin + "/same.js",
              attached: false,
            },
            {
              targetId: "shared",
              type: "shared_worker",
              url: origin + "/shared.js",
              attached: false,
            },
            {
              targetId: "foreign",
              type: "worker",
              url: "https://foreign.example/a.js",
              attached: false,
            },
          ],
        };
      if (
        command.method === "Target.attachToTarget" &&
        command.params.targetId === "shared"
      )
        return { sessionId: "worker-shared" };
      if (
        command.method === "Debugger.getScriptSource" &&
        command.sessionId?.startsWith("worker-")
      )
        return { scriptSource: source };
      return undefined;
    },
    commandEvents(command, origin) {
      const custom = extra.commandEvents?.(command, origin);
      if (custom !== undefined) return custom;
      if (
        command.method === "Target.setAutoAttach" &&
        command.params.autoAttach === true
      )
        return [
          {
            method: "Target.attachedToTarget",
            sessionId: "session-1",
            params: {
              sessionId: "worker-own",
              targetInfo: {
                targetId: "own",
                type: "worker",
                url: origin + "/same.js",
                attached: true,
              },
              waitingForDebugger: false,
            },
          },
        ];
      if (command.sessionId?.startsWith("worker-")) {
        if (command.method === "Runtime.enable")
          return [
            {
              method: "Runtime.executionContextCreated",
              sessionId: command.sessionId,
              params: {
                context: { id: 1, uniqueId: "worker-context", origin },
              },
            },
          ];
        if (command.method === "Debugger.enable")
          return [
            {
              method: "Debugger.scriptParsed",
              sessionId: command.sessionId,
              params: {
                scriptId: "1",
                url: origin + "/same.js",
                executionContextId: 1,
                hash: "producer",
                length: source.length,
              },
            },
          ];
        return [];
      }
      return undefined;
    },
  });
  onTestFinished(() => browser.close());
  const input = inspectWebPageInputSchema.parse({
    cdp_endpoint: browser.endpoint,
    target_id: "allowed-page",
    observation_ms: 0,
    include_script_sources: true,
  });
  return { browser, input, provider: new CdpBrowserProvider() };
}
it("uses session ancestry rather than URL equality and retains unknown ownership", async () => {
  const { provider, input } = await fixture();
  const result = await provider.inspectPage(input);
  if (!result.ok) throw result.error;
  expect(result.value.workers.map((w) => w.target_id)).toEqual([
    "other",
    "own",
    "shared",
  ]);
  expect(
    result.value.workers.find((w) => w.target_id === "other")?.observation,
  ).toMatchObject({ ownership: "unknown", scripts: [] });
  expect(
    result.value.workers.find((w) => w.target_id === "own")?.observation,
  ).toMatchObject({
    ownership: "page_related",
    page_target_id: "allowed-page",
    scripts: [
      {
        script_id: "1",
        execution_context_id: 1,
        source: { included: true, artifact: { text: source } },
      },
    ],
  });
});
it("explicitly selected shared workers remain ownership-unknown", async () => {
  const { provider, input } = await fixture();
  const result = await provider.inspectPage({
    ...input,
    worker_target_ids: ["shared"],
  });
  if (!result.ok) throw result.error;
  expect(
    result.value.workers.find((w) => w.target_id === "shared")?.observation,
  ).toMatchObject({
    ownership: "unknown",
    page_target_id: null,
    selected_explicitly: true,
    scripts: [{ source: { included: true } }],
  });
});
it.each(["foreign", "missing"])(
  "rejects an explicit target outside authorized inventory: %s",
  async (id) => {
    const { provider, input, browser } = await fixture();
    expect(
      await provider.inspectPage({ ...input, worker_target_ids: [id] }),
    ).toMatchObject({ ok: false, error: { reason: "target_not_allowed" } });
    expect(
      browser.commands.some(
        (c) => c.method === "Target.attachToTarget" && c.params.targetId === id,
      ),
    ).toBe(false);
  },
);
it.each([{}, { scriptSource: null }])(
  "rejects malformed worker source: %j",
  async (reply) => {
    const { provider, input } = await fixture({
      commandResult: (c) =>
        c.method === "Debugger.getScriptSource" && c.sessionId === "worker-own"
          ? reply
          : undefined,
    });
    expect(await provider.inspectPage(input)).toMatchObject({
      ok: false,
      error: { reason: "protocol_error" },
    });
  },
);
it("cancellation releases an in-flight source read and attached sessions", async () => {
  const { provider, input, browser } = await fixture({
    hangOnMethod: "Debugger.getScriptSource",
  });
  const controller = new AbortController();
  const pending = provider.inspectPage(input, { signal: controller.signal });
  await vi.waitFor(() =>
    expect(
      browser.commands.some(
        (c) =>
          c.method === "Debugger.getScriptSource" &&
          c.sessionId === "worker-own",
      ),
    ).toBe(true),
  );
  controller.abort();
  expect((await pending).ok).toBe(false);
  await vi.waitFor(() => expect(browser.activeConnectionCount()).toBe(0));
  expect(
    browser.commands.some(
      (c) =>
        c.method === "Target.detachFromTarget" &&
        c.params.sessionId === "worker-own",
    ),
  ).toBe(true);
  expect(
    browser.commands.some(
      (c) =>
        c.method === "Target.closeTarget" ||
        c.method === "Runtime.evaluate" ||
        c.method === "Runtime.runIfWaitingForDebugger",
    ),
  ).toBe(false);
});
it("does not request worker sources when source capture is disabled", async () => {
  const { provider, input, browser } = await fixture();
  const result = await provider.inspectPage({
    ...input,
    include_script_sources: false,
  });
  if (!result.ok) throw result.error;
  expect(
    result.value.workers.find((w) => w.target_id === "own")?.observation
      ?.scripts[0]?.source,
  ).toMatchObject({ included: false });
  expect(
    browser.commands.some(
      (c) =>
        c.method === "Debugger.getScriptSource" && c.sessionId === "worker-own",
    ),
  ).toBe(false);
});

it.each([false, true, null])(
  "retains service worker client evidence before attachment (controls page: %s)",
  async (controls) => {
    const { provider, input, browser } = await fixture({
      eventsBeforeReply: ["ServiceWorker.enable", "Target.setAutoAttach"],
      commandEvents(command, origin) {
        if (command.method === "ServiceWorker.enable")
          return [
            {
              method: "ServiceWorker.workerVersionUpdated",
              sessionId: "session-1",
              params: {
                versions: [
                  {
                    targetId: "service",
                    ...(controls === null
                      ? {}
                      : {
                          controlledClients: controls
                            ? ["allowed-page"]
                            : ["another-page"],
                        }),
                    runningStatus: "running",
                    status: "activated",
                  },
                ],
              },
            },
          ];
        if (
          command.method === "Target.setAutoAttach" &&
          command.params.autoAttach === true
        )
          return [
            {
              method: "Target.attachedToTarget",
              sessionId: "session-1",
              params: {
                sessionId: "worker-service",
                targetInfo: {
                  targetId: "service",
                  type: "service_worker",
                  url: origin + "/service.js",
                  attached: true,
                },
              },
            },
          ];
        if (
          command.method === "Network.enable" &&
          command.sessionId === "worker-service"
        )
          return [
            {
              method: "ServiceWorker.workerVersionUpdated",
              sessionId: "session-1",
              params: {
                versions: [
                  {
                    targetId: "service",
                    controlledClients: [],
                    runningStatus: "running",
                    status: "activated",
                  },
                ],
              },
            },
            {
              method: "Debugger.scriptParsed",
              sessionId: "worker-service",
              params: {
                scriptId: "after-revocation",
                url: origin + "/late.js",
                executionContextId: 1,
              },
            },
          ];
        return undefined;
      },
    });
    const result = await provider.inspectPage(input);
    if (!result.ok) throw result.error;
    const observed = result.value.workers.find(
      (w) => w.target_id === "service",
    )!.observation!;
    expect(observed.ownership).toBe(
      controls ? "service_worker_client" : "unknown",
    );
    expect(observed.lifecycle[0]).toMatchObject({
      event: "version",
      controls_page: controls,
      version_status: "activated",
    });
    expect(observed.scripts).toHaveLength(controls ? 1 : 0);
    expect(
      browser.commands.some((c) => c.params.scriptId === "after-revocation"),
    ).toBe(false);
    if (controls)
      expect(observed.lifecycle.at(-1)).toMatchObject({ controls_page: false });
  },
);

it.each([-32_000, -32_601])(
  "retains worker identity when source retrieval becomes unavailable (%s)",
  async (code) => {
    const { provider, input } = await fixture({
      commandError: (c) =>
        c.method === "Debugger.getScriptSource" && c.sessionId === "worker-own"
          ? { code, message: "Source unavailable" }
          : undefined,
    });
    const result = await provider.inspectPage(input);
    if (!result.ok) throw result.error;
    const observed = result.value.workers.find(
      (w) => w.target_id === "own",
    )!.observation!;
    expect(observed.scripts[0]?.source.included).toBe(false);
    expect(observed.completeness.unavailable_sections).toContain(
      "script_sources",
    );
  },
);
