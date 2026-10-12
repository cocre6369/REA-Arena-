import type { WebPageInspection } from "../domain/browserObservationSchemas.js";
import type { CaptureContext } from "./CdpPageCapture.js";
import type { CdpEvent } from "./CdpConnection.js";
import { CdpCaptureEvents } from "./CdpCaptureEvents.js";
import { optionalCdpCommand } from "./CdpOptionalCommand.js";
import { CdpCommandRejection } from "./CdpCommandRejection.js";
import { BrowserObservationError } from "../domain/browserObservationError.js";
import { WEB_RUNTIME_LIMITS } from "../domain/webRuntime.js";
import { compareUnicodeCodePoints } from "../domain/unicodeCodePointOrder.js";
import {
  allowedSanitizedUrl,
  cdpStringValue,
  numberValue,
  recordValue,
  recordsValue,
  requiredScriptSource,
  sourceExcluded,
  sourceResult,
} from "./CdpCaptureValues.js";

type Worker = WebPageInspection["workers"][number];
type Observation = NonNullable<Worker["observation"]>;
interface WorkerState {
  item: Worker & { observation: Observation };
  sessionId: string | undefined;
  detached: boolean;
  enabled: boolean;
  events: CdpCaptureEvents;
  sources: Map<string, Observation["scripts"][number]>;
}

/** Owns only REA's worker debugger sessions; never pauses, starts or stops workers. */
export class CdpWorkerCapture {
  readonly #workers = new Map<string, WorkerState>();
  readonly #sessions = new Map<string, WorkerState>();
  readonly #controlled = new Set<string>();
  readonly #versionsByTarget = new Map<
    string,
    Observation["lifecycle"][number]
  >();
  readonly #pending = new Set<Promise<void>>();
  readonly #invalidTargets = new Set<string>();
  #failure: unknown;
  #removeListener: (() => void) | undefined;
  #stopped = false;
  #eventBytes = 0;
  #sourceBytes = 0;
  readonly #abort = new AbortController();
  readonly signal: AbortSignal;

  constructor(
    private readonly context: CaptureContext,
    private readonly allowedOrigins: ReadonlySet<string>,
    readonly limitations: string[],
    private readonly pageEvents: CdpCaptureEvents,
  ) {
    this.signal =
      context.signal === undefined
        ? this.#abort.signal
        : AbortSignal.any([context.signal, this.#abort.signal]);
  }

  check(): void {
    if (this.#failure !== undefined) throw this.#failure;
  }

  async start(): Promise<void> {
    this.pageEvents.completeness.attachLimited("workers");
    this.#removeListener = this.context.connection.onEvent((event) => {
      try {
        this.#ingest(event);
      } catch (cause) {
        this.#fail(cause);
      }
    });
    await this.#command("ServiceWorker.enable", {}, this.context.sessionId);
    await this.#command(
      "Target.setAutoAttach",
      {
        autoAttach: true,
        waitForDebuggerOnStart: false,
        flatten: true,
        filter: [
          { type: "worker" },
          { type: "service_worker" },
          { exclude: true },
        ],
      },
      this.context.sessionId,
    );
    await this.#inventory();
    for (const id of this.context.input.worker_target_ids ?? []) {
      const worker = this.#workers.get(id);
      if (worker === undefined)
        throw new BrowserObservationError(
          this.context.operation,
          "target_not_allowed",
        );
      if (worker.sessionId !== undefined) continue;
      const result = recordValue(
        await this.#command(
          "Target.attachToTarget",
          { targetId: id, flatten: true },
          undefined,
        ),
      );
      const sessionId = cdpStringValue(result?.sessionId);
      if (sessionId === undefined)
        throw new BrowserObservationError(
          this.context.operation,
          "protocol_error",
        );
      this.#attach(worker, sessionId);
    }
    await this.#settle();
  }

  async finish(): Promise<Worker[]> {
    await this.#inventory();
    await this.#settle();
    this.#stopped = true;
    return [...this.#workers.values()]
      .map((worker) => {
        worker.events.recordScriptMetadataBudgetExclusions();
        if (!worker.enabled) {
          worker.events.completeness.unavailable("scripts");
          worker.events.completeness.unavailable("network_requests");
        }
        worker.item.observation.network_requests = [
          ...worker.events.network.values(),
        ];
        worker.item.observation.scripts = [...worker.sources.values()];
        worker.item.observation.completeness =
          worker.events.completeness.snapshot();
        if (!worker.enabled)
          worker.item.observation.limitations.push(
            "Worker source and runtime observation unavailable without proven page ownership or explicit target selection.",
          );
        return worker.item;
      })
      .sort((a, b) => compareUnicodeCodePoints(a.target_id, b.target_id));
  }

  async close(): Promise<void> {
    this.#stopped = true;
    this.#removeListener?.();
    this.#abort.abort();
    await Promise.all(this.#pending);
    if (this.#removeListener === undefined) return;
    // The outer page-session owner closes the entire connection even if these
    // optional domain/detach commands fail or the caller has cancelled.
    const signal = AbortSignal.timeout(1000);
    const send = async (
      method: string,
      params: Record<string, unknown>,
      sessionId?: string,
    ): Promise<void> => {
      try {
        await this.context.connection.send(method, params, sessionId, signal);
      } catch {
        /* Socket close is the definitive release boundary. */
      }
    };
    await send(
      "Target.setAutoAttach",
      { autoAttach: false, waitForDebuggerOnStart: false, flatten: true },
      this.context.sessionId,
    );
    await send("ServiceWorker.disable", {}, this.context.sessionId);
    for (const [sessionId, worker] of this.#sessions)
      if (!worker.detached)
        await send("Target.detachFromTarget", { sessionId });
  }

  async #inventory(): Promise<void> {
    const result = await this.#command("Target.getTargets", {}, undefined);
    if (result === undefined)
      this.pageEvents.completeness.unavailable("workers");
    for (const target of recordsValue(recordValue(result)?.targetInfos))
      this.#admit(target);
  }

  #admit(target: Readonly<Record<string, unknown>>): WorkerState | undefined {
    const type = cdpStringValue(target.type);
    if (
      type !== "worker" &&
      type !== "shared_worker" &&
      type !== "service_worker"
    )
      return;
    const id = cdpStringValue(target.targetId);
    if (typeof target.attached !== "boolean") {
      const key = id ?? JSON.stringify(target);
      if (!this.#invalidTargets.has(key)) {
        this.#invalidTargets.add(key);
        this.pageEvents.completeness.exclude(
          "workers",
          "invalid_protocol_value",
        );
      }
      return;
    }
    const url = allowedSanitizedUrl(target.url, this.allowedOrigins);
    if (id === undefined || id === "" || url === undefined) {
      const key = id ?? JSON.stringify(target);
      if (!this.#invalidTargets.has(key)) {
        this.#invalidTargets.add(key);
        this.pageEvents.completeness.exclude(
          "workers",
          url === undefined ? "unattributed_origin" : "invalid_protocol_value",
        );
      }
      return;
    }
    const existing = this.#workers.get(id);
    if (existing !== undefined) return existing;
    const worker: WorkerState = {
      item: {
        target_id: id,
        type,
        url: url.url,
        origin: url.origin,
        attached: target.attached === true,
        opener_target_id: cdpStringValue(target.openerId) ?? null,
        parent_frame_id: cdpStringValue(target.parentFrameId) ?? null,
        observation: {
          ownership: this.#controlled.has(id)
            ? "service_worker_client"
            : "unknown",
          selected_explicitly:
            this.context.input.worker_target_ids?.includes(id) ?? false,
          page_target_id: this.#controlled.has(id)
            ? this.context.target.id
            : null,
          lifecycle: this.#versionsByTarget.has(id)
            ? [this.#versionsByTarget.get(id)!]
            : [],
          execution_contexts: [],
          scripts: [],
          network_requests: [],
          completeness: new CdpCaptureEvents(
            this.context.input,
            this.allowedOrigins,
          ).completeness.snapshot(),
          limitations: [
            "Only events after attachment are observed. Loaded scripts do not prove execution. Worker registration does not prove cached response delivery.",
          ],
        },
      },
      sessionId: undefined,
      detached: false,
      enabled: false,
      events: new CdpCaptureEvents(this.context.input, this.allowedOrigins),
      sources: new Map(),
    };
    this.#workers.set(id, worker);
    return worker;
  }

  #ingest(event: CdpEvent): void {
    if (this.#stopped) return;
    if (
      event.sessionId !== this.context.sessionId &&
      !this.#sessions.has(event.sessionId ?? "") &&
      !(
        event.method === "Target.detachedFromTarget" &&
        this.#sessions.has(
          cdpStringValue(recordValue(event.params)?.sessionId) ?? "",
        )
      )
    )
      return;
    if (
      !event.method.startsWith("Target.") &&
      !event.method.startsWith("ServiceWorker.") &&
      event.sessionId === this.context.sessionId
    )
      return;
    this.#eventBytes += Buffer.byteLength(JSON.stringify(event));
    if (this.#eventBytes > WEB_RUNTIME_LIMITS.retainedEventBytes)
      throw new BrowserObservationError(
        this.context.operation,
        "payload_limit",
      );
    const params = recordValue(event.params);
    if (params === undefined) return;
    if (
      event.method === "ServiceWorker.workerVersionUpdated" &&
      event.sessionId === this.context.sessionId
    ) {
      this.#versions(params);
      return;
    }
    if (event.method === "Target.attachedToTarget") {
      const parent =
        event.sessionId === this.context.sessionId
          ? undefined
          : this.#sessions.get(event.sessionId ?? "");
      if (event.sessionId !== this.context.sessionId && parent === undefined)
        return;
      const info = recordValue(params.targetInfo);
      const sessionId = cdpStringValue(params.sessionId);
      const worker = info === undefined ? undefined : this.#admit(info);
      if (worker === undefined || sessionId === undefined) return;
      if (
        worker.item.type === "worker" &&
        (parent === undefined ||
          parent.item.observation.ownership === "page_related")
      ) {
        worker.item.observation.ownership = "page_related";
        worker.item.observation.page_target_id = this.context.target.id;
      }
      this.#attach(worker, sessionId);
      return;
    }
    if (event.method === "Target.detachedFromTarget") {
      const worker = this.#sessions.get(cdpStringValue(params.sessionId) ?? "");
      if (worker !== undefined) {
        worker.detached = true;
        worker.item.observation.lifecycle.push({
          event: "detached",
          observed_at: new Date().toISOString(),
          running_status: null,
          version_status: null,
          controls_page: null,
        });
      }
      return;
    }
    const worker = this.#sessions.get(event.sessionId ?? "");
    if (worker === undefined || !worker.enabled || worker.detached) return;
    if (
      worker.item.type === "service_worker" &&
      !this.#controlled.has(worker.item.target_id) &&
      !worker.item.observation.selected_explicitly
    )
      return;
    worker.events.ingest(event);
    if (event.method === "Runtime.executionContextCreated") {
      const context = recordValue(params.context);
      const id = numberValue(context?.id);
      if (id !== undefined && Number.isSafeInteger(id))
        worker.item.observation.execution_contexts.push({
          id,
          unique_id: cdpStringValue(context?.uniqueId) ?? null,
          origin:
            allowedSanitizedUrl(context?.origin, this.allowedOrigins)?.origin ??
            null,
        });
    }
    if (event.method === "Debugger.scriptParsed") this.#script(worker, params);
  }

  #script(
    worker: WorkerState,
    params: Readonly<Record<string, unknown>>,
  ): void {
    const scriptId = cdpStringValue(params.scriptId);
    const script = worker.events.scripts.get(scriptId ?? "");
    if (script === undefined) return;
    const contextId = numberValue(params.executionContextId);
    const item: Observation["scripts"][number] = {
      script_id: script.scriptId,
      is_module: script.isModule,
      language: script.language,
      source_map_url: script.sourceMapUrl,
      execution_context_id:
        contextId !== undefined && Number.isSafeInteger(contextId)
          ? contextId
          : null,
      url: script.url,
      cdp_hash: script.hash,
      source: sourceExcluded("source capture was not selected"),
    };
    const previous = worker.sources.get(script.scriptId);
    if (previous !== undefined) {
      if (
        previous.url !== item.url ||
        previous.cdp_hash !== item.cdp_hash ||
        previous.execution_context_id !== item.execution_context_id ||
        previous.is_module !== item.is_module ||
        previous.language !== item.language ||
        previous.source_map_url !== item.source_map_url
      )
        throw new BrowserObservationError(
          this.context.operation,
          "target_changed",
        );
      return;
    }
    worker.sources.set(script.scriptId, item);
    if (this.context.input.include_script_sources)
      this.#queue(async () => {
        try {
          const source = await this.#command(
            "Debugger.getScriptSource",
            { scriptId: script.scriptId },
            worker.sessionId,
            worker.item.observation.limitations,
          );
          if (source === undefined) {
            item.source = sourceExcluded(
              "Worker source retrieval is unavailable",
            );
            worker.events.completeness.unavailable("script_sources");
            return;
          }
          const text = requiredScriptSource(source, this.context.operation);
          this.#sourceBytes += Buffer.byteLength(text);
          if (this.#sourceBytes > WEB_RUNTIME_LIMITS.sourceBytes)
            throw new BrowserObservationError(
              this.context.operation,
              "payload_limit",
            );
          item.source = sourceResult(text);
        } catch (cause) {
          if (
            !this.signal.aborted &&
            cause instanceof CdpCommandRejection &&
            cause.code === -32_000
          ) {
            item.source = sourceExcluded(
              "Worker source became unavailable during capture",
            );
            worker.events.completeness.unavailable("script_sources");
          } else throw cause;
        }
      });
  }

  #versions(params: Readonly<Record<string, unknown>>): void {
    for (const version of recordsValue(params.versions)) {
      const id = cdpStringValue(version.targetId);
      if (id === undefined) continue;
      const controls = Array.isArray(version.controlledClients)
        ? version.controlledClients.includes(this.context.target.id)
        : null;
      if (controls) this.#controlled.add(id);
      else this.#controlled.delete(id);
      const lifecycle: Observation["lifecycle"][number] = {
        event: "version",
        observed_at: new Date().toISOString(),
        running_status: cdpStringValue(version.runningStatus) ?? null,
        version_status: cdpStringValue(version.status) ?? null,
        controls_page: controls,
      };
      this.#versionsByTarget.set(id, lifecycle);
      const worker = this.#workers.get(id);
      if (worker === undefined) continue;
      if (controls) {
        worker.item.observation.ownership = "service_worker_client";
        worker.item.observation.page_target_id = this.context.target.id;
      }
      worker.item.observation.lifecycle.push(lifecycle);
      if (worker.sessionId !== undefined)
        this.#queue(() => this.#enable(worker));
    }
  }

  #attach(worker: WorkerState, sessionId: string): void {
    if (worker.sessionId === sessionId) return;
    if (worker.sessionId !== undefined)
      throw new BrowserObservationError(
        this.context.operation,
        "target_changed",
      );
    worker.sessionId = sessionId;
    this.#sessions.set(sessionId, worker);
    worker.item.observation.lifecycle.push({
      event: "attached",
      observed_at: new Date().toISOString(),
      running_status: null,
      version_status: null,
      controls_page: null,
    });
    this.#queue(() => this.#enable(worker));
  }

  async #enable(worker: WorkerState): Promise<void> {
    if (
      worker.enabled ||
      worker.detached ||
      (!worker.item.observation.selected_explicitly &&
        worker.item.observation.ownership === "unknown")
    )
      return;
    worker.enabled = true;
    for (const domain of ["Runtime", "Debugger", "Network"]) {
      if (worker.detached) return;
      try {
        const result = await this.#command(
          `${domain}.enable`,
          {},
          worker.sessionId,
          worker.item.observation.limitations,
        );
        if (result === undefined && domain !== "Runtime")
          worker.events.completeness.unavailable(
            domain === "Debugger" ? "scripts" : "network_requests",
          );
      } catch (cause) {
        if (
          !this.signal.aborted &&
          cause instanceof CdpCommandRejection &&
          cause.code === -32_000
        ) {
          worker.item.observation.limitations.push(
            `${domain} became unavailable during worker attachment.`,
          );
          worker.events.completeness.unavailable("scripts");
          worker.events.completeness.unavailable("network_requests");
          return;
        }
        throw cause;
      }
    }
  }

  async #command(
    method: string,
    params: Record<string, unknown>,
    sessionId: string | undefined,
    limitations = this.limitations,
  ): Promise<unknown> {
    const timeout = AbortSignal.timeout(WEB_RUNTIME_LIMITS.commandTimeoutMs);
    try {
      return await optionalCdpCommand(
        {
          connection: this.context.connection,
          sessionId,
          signal: AbortSignal.any([this.signal, timeout]),
        },
        method,
        params,
        limitations,
      );
    } catch (cause) {
      if (timeout.aborted && !this.signal.aborted)
        throw new BrowserObservationError(this.context.operation, "timeout", {
          cause,
        });
      throw cause;
    }
  }

  #queue(work: () => Promise<void>): void {
    const pending = work()
      .catch((cause) => {
        this.#fail(cause);
      })
      .finally(() => this.#pending.delete(pending));
    this.#pending.add(pending);
  }
  async #settle(): Promise<void> {
    while (this.#pending.size > 0) await Promise.all(this.#pending);
    if (this.#failure !== undefined) throw this.#failure;
  }
  #fail(cause: unknown): void {
    if (this.#failure === undefined) this.#failure = cause;
    this.#abort.abort();
  }
}
