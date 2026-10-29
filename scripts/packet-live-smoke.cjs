const assert = require("node:assert/strict");
const path = require("node:path");
const dns = require("node:dns");
const dgram = require("node:dgram");
const fs = require("node:fs/promises");
const { Packets } = require("../electron/packets.cjs");
(async () => {
  const manager = new Packets(null, {
    snapshot: () => ({ admin: true, flows: [] }),
    agentPath: path.join(
      __dirname,
      "../native/bin",
      require("../package.json").version,
      "Watchmen.Agent.exe",
    ),
  });
  const socket = dgram.createSocket("udp4");
  socket.on("error", () => {});
  const server = dns.getServers().find((s) => /^\d+\.\d+\.\d+\.\d+$/.test(s));
  assert.ok(server, "An IPv4 DNS server is needed for the controlled probe.");
  const query = Buffer.concat([
    Buffer.from([0x57, 0x4d, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 21]),
    Buffer.from("watchmen-packet-probe"),
    Buffer.from([7]),
    Buffer.from("invalid"),
    Buffer.from([0, 0, 1, 0, 1]),
  ]);
  let interval;
  try {
    await manager.start(5);
    const send = () => socket.send(query, 53, server, () => {});
    send();
    interval = setInterval(send, 120);
    await manager.completion;
    const state = manager.status();
    const probes = state.packets
      .map((p) => manager.detail(p.id))
      .filter(
        (p) =>
          p.protocol === "DNS" &&
          p.payloadText.includes("watchmen-packet-probe.invalid"),
      );
    const result = {
      captured: state.totalRecords,
      displayed: state.packets.length,
      controlledReadableDNS: probes.length,
      outgoingProbe: probes.some((p) => p.direction === "Outgoing"),
      incomingProbe: probes.some((p) => p.direction === "Incoming"),
      activeAfterCompletion: state.active,
      error: state.error,
    };
    await fs.writeFile(
      path.join(__dirname, "../test-results/packet-live-smoke.json"),
      JSON.stringify(result, null, 2),
    );
    console.log(JSON.stringify(result));
    assert.equal(result.error, null);
    assert.ok(
      result.controlledReadableDNS > 0,
      "Controlled DNS query was not decoded.",
    );
    assert.equal(result.outgoingProbe, true);
    assert.equal(result.activeAfterCompletion, false);
  } finally {
    clearInterval(interval);
    socket.close();
    await manager.shutdown();
  }
})().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
