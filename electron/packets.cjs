const { spawn } = require("node:child_process");
const { createInterface } = require("node:readline");
const fs = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");
const { parseCapture, decodeFrame } = require("./packet-decode.cjs");
const empty = () => ({
  packets: [],
  totalRecords: 0,
  displayLimit: 500,
  limited: false,
});
class Packets {
  constructor(
    directory,
    { snapshot = () => null, agentPath = null, spawnAgent = spawn } = {},
  ) {
    this.directory = directory;
    this.snapshot = snapshot;
    this.agentPath = agentPath;
    this.spawnAgent = spawnAgent;
    this.result = empty();
    this.error = null;
    this.active = null;
    this.processing = false;
    this.child = null;
    this.completion = null;
    this.source = "";
    this.closing = false;
  }
  context() {
    return {
      localAddresses: [
        "127.0.0.1",
        "::1",
        ...Object.values(os.networkInterfaces())
          .flat()
          .filter(Boolean)
          .map((a) => a.address),
      ],
      flows: this.snapshot()?.flows || [],
    };
  }
  status() {
    return {
      active: !!this.active,
      processing: this.processing,
      error: this.error,
      source: this.source,
      startedAt: this.active?.startedAt || null,
      endsAt: this.active?.endsAt || null,
      ...this.result,
      packets: this.result.packets.map(
        ({ payloadText, headers, hexHeaders, ...p }) => p,
      ),
    };
  }
  async start(seconds = 10) {
    if (![5, 10, 20, 30].includes(seconds))
      throw new Error("Choose a 5–30 second capture.");
    if (this.active || this.processing)
      throw new Error("A packet capture is already in progress.");
    if (!this.snapshot()?.admin)
      throw new Error(
        "Restart Watchmen as administrator to capture packets. PCAP import works without elevation.",
      );
    if (!this.agentPath)
      throw new Error("The native packet collector is unavailable.");
    this.processing = true;
    this.error = null;
    this.result = empty();
    const startedAt = Date.now();
    this.active = { startedAt, endsAt: startedAt + seconds * 1000 };
    this.source =
      "Windows IPv4 packet capture · " +
      new Date(startedAt).toLocaleTimeString();
    let child;
    try {
      child = this.spawnAgent(
        this.agentPath,
        ["--raw-packets", String(seconds)],
        { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] },
      );
    } catch {
      this.active = null;
      this.processing = false;
      throw new Error("The native packet collector could not be launched.");
    }
    this.child = child;
    child.stdin.on("error", () => {});
    let ready = false;
    let resolveStart, rejectStart;
    const startup = new Promise((resolve, reject) => {
      resolveStart = resolve;
      rejectStart = reject;
    });
    const timer = setTimeout(
      () => {
        this.error = "The packet collector did not finish in time.";
        child.stdin.end();
        child.kill();
      },
      (seconds + 5) * 1000,
    );
    this.completion = new Promise((resolve) => {
      let finished = false;
      const done = () => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        this.active = null;
        this.processing = false;
        this.child = null;
        if (!ready) {
          const message = this.error || "The packet collector could not start.";
          this.error = message;
          rejectStart(new Error(message));
        }
        resolve(this.status());
      };
      child.on("error", () => {
        this.error = "The native packet collector could not be launched.";
        done();
      });
      child.on("close", done);
      child.stderr.on("data", () => {
        this.error = "The native packet collector reported an error.";
      });
      createInterface({ input: child.stdout }).on("line", (line) => {
        try {
          const message = JSON.parse(line);
          if (message.type === "ready") {
            ready = true;
            this.processing = false;
            resolveStart(this.status());
          } else if (message.type === "error") {
            this.error = String(
              message.message || "Packet capture failed.",
            ).slice(0, 300);
            rejectStart(new Error(this.error));
          } else if (message.type === "packet") {
            this.result.totalRecords++;
            if (this.result.packets.length < 500) {
              const packet = decodeFrame(Buffer.from(message.data, "base64"), {
                ...this.context(),
                linkType: 101,
                timestamp: message.timestamp,
                originalLength: message.length,
                id: String(this.result.totalRecords),
              });
              this.result.packets.push(packet);
            }
          } else if (message.type === "done") {
            this.result.totalRecords =
              Number(message.totalRecords) || this.result.totalRecords;
            this.result.limited = this.result.totalRecords > 500;
          }
        } catch {
          this.error = "The native packet collector returned unreadable data.";
        }
      });
    });
    return startup;
  }
  async stop() {
    if (this.child) {
      this.child.stdin.end();
      return this.completion;
    }
    return this.status();
  }
  async importFile(filename) {
    if (this.active || this.processing)
      throw new Error("Finish the current capture before importing a file.");
    this.processing = true;
    try {
      const stat = await fs.stat(filename);
      if (stat.size > 64 * 1024 * 1024)
        throw new Error("Capture files are limited to 64 MB.");
      this.result = parseCapture(await fs.readFile(filename), this.context());
      this.source = path.basename(filename);
      this.error = null;
    } finally {
      this.processing = false;
    }
    return this.status();
  }
  detail(id) {
    const packet = this.result.packets.find((p) => p.id === String(id));
    if (!packet) throw new Error("Select a captured packet.");
    return packet;
  }
  async shutdown() {
    this.closing = true;
    await this.stop();
    this.result = empty();
  }
}
module.exports = { Packets };
