const { spawn } = require("node:child_process");
const { randomUUID } = require("node:crypto");
const { isIP } = require("node:net");
const path = require("node:path");
const { Regions, countries, countryCodes } = require("./regions.cjs");
function nativeRequest(agentPath, request) {
  return new Promise((resolve, reject) => {
    const child = spawn(agentPath, ["--firewall"], {
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let output = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(
        new Error(
          "Windows took too long to update rules. Refresh the rules view to verify the result.",
        ),
      );
    }, 300000);
    child.stdin.on("error", () => {});
    child.on("error", () => {
      clearTimeout(timer);
      reject(new Error("The Windows network-rule helper could not start."));
    });
    child.stdout.on("data", (data) => {
      output += data.toString();
      if (output.length > 4 * 1024 * 1024) {
        child.kill();
        reject(new Error("The network-rule response exceeds its size limit."));
      }
    });
    child.stderr.on("data", () => {});
    child.on("close", () => {
      clearTimeout(timer);
      try {
        const result = JSON.parse(output);
        if (result.ok) resolve(result.value);
        else
          reject(
            new Error(result.error || "Windows could not apply the rule."),
          );
      } catch (error) {
        reject(
          error instanceof SyntaxError
            ? new Error(
                "The network-rule helper returned an unreadable response.",
              )
            : error,
        );
      }
    });
    child.stdin.end(JSON.stringify(request));
  });
}
class Firewall {
  constructor(
    directory,
    {
      agentPath,
      snapshot = () => null,
      fetch,
      transport = (request) => nativeRequest(agentPath, request),
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
    } else if (rule.kind === "region") {
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
      const prepared = await this.regions.prepare(rule.countries);
      rule.sourceMonth = prepared.sourceMonth;
      rule.rangeCount = prepared.rangeCount;
      rule.nativeRuleCount = prepared.rangeCount * 2;
      for (const [id, value] of this.previews)
        if (value.rule.kind === "region") this.previews.delete(id);
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
      if (rule.kind === "region" && !ranges.length)
        throw new Error("Review the country ranges before applying this rule.");
      this.phase = "Applying persistent Windows rules…";
      const value = await this.transport({ action: "add", rule, ranges });
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
      this.transport({ action: "set-enabled", id, enabled }),
    );
  }
  async forget(id) {
    if (
      typeof id !== "string" ||
      !this.state.rules.some((rule) => rule.id === id && !rule.enabled)
    )
      throw new Error("Unblock this rule before removing it.");
    return this.mutate(() => this.transport({ action: "forget", id }));
  }
  async unblockAll() {
    return this.mutate(() => this.transport({ action: "unblock-all" }));
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
    try {
      if (this.refreshing) await this.refreshing;
      this.state = await action();
      this.error = null;
    } catch (error) {
      this.error = error.message;
      try {
        this.state = await this.transport({ action: "list" });
      } catch {}
      throw error;
    } finally {
      this.busy = false;
      this.phase = "";
    }
    return this.status();
  }
}
module.exports = { Firewall, nativeRequest };
