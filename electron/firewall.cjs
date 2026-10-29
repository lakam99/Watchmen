const { spawn } = require("node:child_process");

const { randomUUID } = require("node:crypto");

const { isIP } = require("node:net");

const path = require("node:path");

const { Regions, countries, countryCodes } = require("./regions.cjs");

function nativeRequest(
  agentPath,
  request,
  {
    onProgress,
    signal,
    spawnHelper = spawn,
    idleMs = 60000,
    cancelGraceMs = 20000,
  } = {},
) {
  return new Promise((resolve, reject) => {
    const controlled = request.action !== "list" && !!onProgress;

    const child = spawnHelper(agentPath, ["--firewall"], {
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });

    let output = "",
      result,
      settled = false,
      timer,
      cancelTimer;

    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(cancelTimer);
      signal?.removeEventListener("abort", cancel);
      error ? reject(error) : resolve(value);
    };

    const failUnknown = (message) => {
      const error = new Error(
        message + " Refresh rules to verify committed state.",
      );
      error.verificationNeeded = true;
      finish(error);
      child.kill();
    };

    const resetTimer = () => {
      clearTimeout(timer);
      timer = setTimeout(
        () => failUnknown("The Windows helper stopped responding."),
        request.action === "list" ? 20000 : idleMs,
      );
    };

    const cancel = () => {
      if (!controlled) return;
      child.stdin.write("cancel\n");
      cancelTimer = setTimeout(
        () => failUnknown("Windows did not acknowledge cancellation."),
        cancelGraceMs,
      );
    };

    const line = (value) => {
      if (!value.trim()) return;
      const item = JSON.parse(value);
      if (item.type === "progress") {
        onProgress?.(item);
      } else result = item;
    };

    child.stdin.on("error", () => {});

    child.on("error", () =>
      finish(new Error("The Windows network-rule helper could not start.")),
    );

    child.stdout.on("data", (data) => {
      if (settled) return;
      resetTimer();
      output += data.toString();
      if (output.length > 4 * 1024 * 1024)
        return failUnknown("The network-rule response exceeds its size limit.");
      try {
        let end;
        while ((end = output.indexOf("\n")) >= 0) {
          line(output.slice(0, end));
          output = output.slice(end + 1);
        }
      } catch {
        failUnknown("The Windows helper returned an unreadable response.");
      }
    });

    child.stderr.on("data", () => {});

    child.on("close", () => {
      if (settled) return;
      try {
        if (output.trim()) line(output);
        if (!result) {
          const error = new Error(
            "The Windows helper exited without confirming the result. Refresh rules to check committed state.",
          );
          error.verificationNeeded = true;
          throw error;
        }
        if (result.ok) finish(null, result.value);
        else {
          const error = new Error(
            result.error || "Windows could not apply the rule.",
          );
          error.cancelled = !!result.cancelled;
          finish(error);
        }
      } catch (error) {
        finish(error);
      }
    });

    resetTimer();

    if (controlled) {
      child.stdin.write(JSON.stringify({ ...request, control: true }) + "\n");
      signal?.addEventListener("abort", cancel, { once: true });
      if (signal?.aborted) cancel();
    } else child.stdin.end(JSON.stringify(request) + "\n");
  });
}

class Firewall {
  constructor(
    directory,

    {
      agentPath,

      snapshot = () => null,

      fetch,

      transport = (request, options) =>
        nativeRequest(agentPath, request, options),
    },
  ) {
    this.snapshot = snapshot;

    this.transport = transport;

    this.state = {
      rules: [],

      admin: false,

      profiles: [],

      isolationVerified: false,

      verificationError: null,

      updatedAt: null,
    };

    this.error = null;

    this.busy = false;

    this.phase = "";

    this.previews = new Map();

    this.job = null;

    this.controller = null;

    this.regions = new Regions(path.join(directory, "country-ranges"), {
      fetch,

      progress: (phase) => {
        this.phase = phase;
      },
    });

    this.refreshing = null;
  }

  status() {
    return {
      ...this.state,

      error: this.error,

      busy: this.busy,

      phase: this.phase,

      job: this.job,
    };
  }

  catalog() {
    return this.regions.catalog();
  }

  async refresh() {
    if (this.busy) return this.status();

    if (this.refreshing) return this.refreshing;

    this.refreshing = (async () => {
      try {
        this.state = await this.transport({ action: "list" });

        this.error = null;
      } catch (error) {
        this.error = error.message;
      } finally {
        this.refreshing = null;
      }

      return this.status();
    })();

    return this.refreshing;
  }

  prepare(input) {
    if (this.busy)
      throw new Error("Wait for the current rule change to finish.");

    if (!input || typeof input !== "object")
      throw new Error("Choose a network rule.");

    const rule = {
      kind: input.kind,

      label: "",

      appPath: "",

      address: "",

      protocol: "",

      port: 0,

      countries: [],
    };

    const flow = this.snapshot()?.flows?.find((f) => f.id === input.flowId);

    if (["app", "connection", "destination", "onlyApp"].includes(rule.kind)) {
      if (!flow)
        throw new Error(
          "This connection is no longer in the current view. Refresh and select it again.",
        );

      if (["app", "connection", "onlyApp"].includes(rule.kind)) {
        if (
          !flow.processPath ||
          !path.win32.isAbsolute(flow.processPath) ||
          !flow.processPath.toLowerCase().endsWith(".exe")
        )
          throw new Error(
            "The executable path is unavailable for this connection. Block its destination instead.",
          );

        rule.appPath = flow.processPath;

        rule.label = String(flow.app).slice(0, 160);
      }

      if (["connection", "destination"].includes(rule.kind)) {
        if (
          !isIP(flow.remoteAddress) ||
          ["0.0.0.0", "::"].includes(flow.remoteAddress)
        )
          throw new Error(
            "Choose a connection with a specific remote address.",
          );

        rule.address = flow.remoteAddress;

        if (rule.kind === "destination") rule.label = flow.remoteAddress;
      }

      if (rule.kind === "connection") {
        if (
          !["TCP", "UDP"].includes(flow.protocol) ||
          flow.remotePort < 1 ||
          flow.remotePort > 65535
        )
          throw new Error("Choose a remote TCP or UDP connection.");

        rule.port = flow.remotePort;

        rule.protocol = flow.protocol;

        rule.label = String(
          flow.app + " → " + flow.remoteAddress + ":" + flow.remotePort,
        ).slice(0, 160);
      }
    } else if (["region", "onlyRegion"].includes(rule.kind)) {
      if (rule.kind === "onlyRegion") {
        rule.allowLocalNetwork = input.allowLocalNetwork !== false;
        rule.allowUnknown = input.allowUnknown === true;
      }

      rule.countries = countryCodes(input.countries);

      rule.label =
        rule.countries.length <= 3
          ? rule.countries

              .map((code) => countries.find((c) => c.code === code).name)

              .join(", ")

              .slice(0, 160)
          : rule.countries.length + " countries";

      return this.prepareRegion(rule);
    } else throw new Error("Choose a supported network rule.");

    return this.preview(rule);
  }

  prepareExecutable(filename, name, only = false) {
    if (
      !path.win32.isAbsolute(filename) ||
      !filename.toLowerCase().endsWith(".exe")
    )
      throw new Error("Choose an executable.");

    return this.preview({
      kind: only ? "onlyApp" : "app",

      label: name.slice(0, 160),

      appPath: filename,

      address: "",

      protocol: "",

      port: 0,

      countries: [],
    });
  }

  async prepareRegion(rule) {
    this.busy = true;

    this.phase = "Preparing country ranges for review…";

    this.error = null;

    try {
      const prepared = await this.regions.prepare(rule.countries, {
        exclusive: rule.kind === "onlyRegion",
        allowLocalNetwork: rule.allowLocalNetwork,
        allowUnknown: rule.allowUnknown,
      });

      rule.sourceMonth = prepared.sourceMonth;

      rule.rangeCount = prepared.rangeCount;

      rule.nativeRuleCount = prepared.rangeCount * 2;

      for (const [id, value] of this.previews)
        if (["region", "onlyRegion"].includes(value.rule.kind))
          this.previews.delete(id);

      return this.preview(rule, prepared.ranges);
    } catch (error) {
      this.error = error.message;

      throw error;
    } finally {
      this.busy = false;

      this.phase = "";
    }
  }

  preview(rule, ranges = []) {
    const now = Date.now();

    for (const [id, preview] of this.previews)
      if (preview.expires < now) this.previews.delete(id);

    if (this.previews.size >= 20)
      this.previews.delete(this.previews.keys().next().value);

    const preview = { id: randomUUID(), rule, expires: now + 300000 };

    this.previews.set(preview.id, structuredClone({ ...preview, ranges }));

    return preview;
  }

  async apply(id) {
    const preview = this.previews.get(id);

    if (!preview || preview.expires < Date.now())
      throw new Error("This preview expired. Review the rule again.");

    return this.mutate(async () => {
      const rule = structuredClone(preview.rule);

      const ranges = preview.ranges || [];

      if (["region", "onlyRegion"].includes(rule.kind) && !ranges.length)
        throw new Error("Review the country ranges before applying this rule.");

      this.phase = "Applying persistent Windows rules…";

      const value = await this.change({ action: "add", rule, ranges });

      this.previews.delete(id);

      return value;
    });
  }

  async toggle(id, enabled) {
    if (
      typeof id !== "string" ||
      typeof enabled !== "boolean" ||
      !this.state.rules.some((rule) => rule.id === id)
    )
      throw new Error("Choose a saved network rule.");

    return this.mutate(() =>
      this.change({ action: "set-enabled", id, enabled }),
    );
  }

  async forget(id) {
    if (
      typeof id !== "string" ||
      !this.state.rules.some((rule) => rule.id === id && !rule.enabled)
    )
      throw new Error("Unblock this rule before removing it.");

    return this.mutate(() => this.change({ action: "forget", id }));
  }

  async unblockAll() {
    return this.mutate(() => this.change({ action: "unblock-all" }));
  }

  change(request) {
    return this.transport(request, {
      signal: this.controller.signal,
      onProgress: (progress) => {
        const {
          stage,
          message,
          completed,
          total,
          canCancel,
          updatedAt,
          lastAdvancedAt,
        } = progress;

        this.phase = message;

        this.job = {
          ...this.job,
          stage,
          message,
          completed,
          total,
          canCancel: canCancel && !this.controller.signal.aborted,
          updatedAt,
          lastAdvancedAt,
        };
      },
    });
  }

  cancel() {
    if (!this.busy || !this.controller || !this.job?.canCancel)
      throw new Error("This operation cannot be cancelled at this stage.");

    this.controller.abort();
    this.job = {
      ...this.job,
      canCancel: false,
      message: "Cancellation requested; waiting for Windows to roll back…",
    };

    return this.status();
  }

  async mutate(action) {
    if (this.busy)
      throw new Error("Another network-rule change is in progress.");

    if (!this.snapshot()?.admin)
      throw new Error(
        "Restart Watchmen as administrator to change network rules.",
      );

    this.busy = true;

    this.phase = "Updating Windows network rules…";

    this.controller = new AbortController();

    this.job = {
      id: randomUUID(),
      status: "running",
      stage: "queued",
      message: this.phase,
      completed: 0,
      total: 0,
      canCancel: true,
      startedAt: new Date().toISOString(),
      lastAdvancedAt: new Date().toISOString(),
    };

    try {
      if (this.refreshing) await this.refreshing;

      this.state = await action();

      this.error = null;

      const verified = this.state.isolationVerified !== false;

      this.job = {
        ...this.job,
        status: verified ? "completed" : "needsVerification",
        canCancel: false,
        message: verified
          ? "Windows committed and verified the rules."
          : "Windows committed the change, but verification is unavailable. Refresh rules.",
        endedAt: new Date().toISOString(),
      };
    } catch (error) {
      this.error = error.message;

      this.job = {
        ...this.job,
        status: error.cancelled
          ? "cancelled"
          : error.verificationNeeded
            ? "needsVerification"
            : "failed",
        message: error.message,
        canCancel: false,
        endedAt: new Date().toISOString(),
      };

      try {
        this.state = await this.transport({ action: "list" });
      } catch {}

      throw error;
    } finally {
      this.busy = false;

      this.controller = null;

      this.phase = "";
    }

    return this.status();
  }
}

module.exports = { Firewall, nativeRequest };
