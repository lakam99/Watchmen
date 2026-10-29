// Controlled IPv4 / IPv6 loopback TCP and UDP traffic proves socket attribution and,
// when launched as administrator, ETW byte direction. No Internet access is used.
const { spawn } = require("node:child_process");
const { createInterface } = require("node:readline");
const net = require("node:net");
const dgram = require("node:dgram");
const fs = require("node:fs/promises");
(async () => {
  const child = spawn(
    require("node:path").join(
      "native",
      "bin",
      require("../package.json").version,
      "Watchmen.Agent.exe",
    ),
    [],
    {
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  let snapshots = [],
    errors = "";
  child.stderr.on("data", (d) => (errors += d));
  createInterface({ input: child.stdout }).on("line", (l) => {
    try {
      snapshots.push(JSON.parse(l));
    } catch {}
  });
  const delay = (ms) => new Promise((r) => setTimeout(r, ms));
  const servers = [],
    clients = [],
    udp = [];
  try {
    for (const host of ["127.0.0.1", "::1"]) {
      const server = net.createServer((s) =>
        s.on("data", (d) => s.write(Buffer.concat([d, d]))),
      );
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, host, resolve);
      });
      servers.push(server);
      const client = net.createConnection({
        host,
        port: server.address().port,
      });
      client.on("data", () => {});
      clients.push(client);
      await new Promise((r) => client.once("connect", r));
      const s = dgram.createSocket(host.includes(":") ? "udp6" : "udp4");
      await new Promise((r) => s.bind(0, host, r));
      udp.push(s);
      s.on("message", (b, rinfo) => {
        if (b[0] === 1)
          s.send(Buffer.alloc(8192, 2), rinfo.port, rinfo.address);
      });
      const sender = dgram.createSocket(host.includes(":") ? "udp6" : "udp4");
      await new Promise((r) => sender.bind(0, host, r));
      sender.on("message", () => {});
      udp.push(sender);
    }
    await delay(2000);
    for (let i = 0; i < 12; i++) {
      for (const c of clients) c.write(Buffer.alloc(64 * 1024, 1));
      for (let j = 0; j < udp.length; j += 2)
        udp[j + 1].send(
          Buffer.alloc(4096, 1),
          udp[j].address().port,
          udp[j].address().address,
        );
      await delay(200);
    }
    await delay(2000);
    const s = snapshots.at(-1);
    if (!s) throw new Error("No snapshots: " + errors);
    if (s.admin && !s.tracing)
      throw new Error("Administrator ETW capture failed: " + s.traceError);
    const own = s.flows.filter((f) => f.pid === process.pid);
    for (const host of ["127.0.0.1", "::1"])
      if (!own.some((f) => f.protocol === "TCP" && f.remoteAddress === host))
        throw new Error("Missing TCP attribution for " + host);
    if (!own.some((f) => f.protocol === "UDP"))
      throw new Error("Missing UDP socket ownership");
    if (s.errors.length) throw new Error(s.errors.join("; "));
    const captured = own.filter((f) => f.received > 0 && f.sent > 0);
    if (s.tracing) {
      for (const host of ["127.0.0.1", "::1"])
        for (const proto of ["TCP", "UDP"])
          if (
            !captured.some(
              (f) => f.protocol === proto && f.remoteAddress === host,
            )
          )
            throw new Error(`No bidirectional ETW bytes for ${proto} ${host}`);
      for (const c of clients) {
        const flow = own.find(
          (f) =>
            f.protocol === "TCP" &&
            f.localPort === c.localPort &&
            f.remotePort === c.remotePort,
        );
        if (!flow || flow.sent < 12 * 65536 || flow.received < flow.sent * 1.5)
          throw new Error(
            "TCP byte direction or accounting incorrect for " +
              c.localAddress +
              ": " +
              JSON.stringify({
                sent: flow?.sent,
                received: flow?.received,
                localPort: c.localPort,
                remotePort: c.remotePort,
                related: own
                  .filter(
                    (f) =>
                      f.protocol === "TCP" &&
                      [c.localPort, c.remotePort].includes(f.localPort),
                  )
                  .map((f) => ({
                    localPort: f.localPort,
                    remotePort: f.remotePort,
                    sent: f.sent,
                    received: f.received,
                  })),
              }),
          );
      }
      for (let j = 0; j < udp.length; j += 2) {
        const sender = udp[j + 1],
          server = udp[j];
        const flow = own.find(
          (f) =>
            f.protocol === "UDP" &&
            f.localPort === sender.address().port &&
            f.remotePort === server.address().port,
        );
        if (!flow || flow.sent < 12 * 4096 || flow.received < flow.sent * 1.5)
          throw new Error(
            "UDP byte direction or accounting incorrect for " +
              sender.address().address,
          );
      }
      if (s.eventsLost > 0)
        throw new Error("Trace events were lost during the controlled test");
    }
    const result = {
      passed: true,
      admin: s.admin,
      tracing: s.tracing,
      traceError: s.traceError,
      snapshots: snapshots.length,
      flows: s.flows.length,
      ownedTestFlows: own.length,
      bidirectionalTestFlows: captured.length,
      adapters: s.adapters.length,
      etwVerified: s.tracing,
      directionalAccountingVerified: s.tracing,
      eventsLost: s.eventsLost,
    };
    await fs.mkdir("test-results", { recursive: true });
    await fs.writeFile(
      "test-results/collector-smoke.json",
      JSON.stringify(result, null, 2),
    );
    console.log(JSON.stringify(result, null, 2));
  } finally {
    clients.forEach((c) => c.destroy());
    servers.forEach((s) => s.close());
    udp.forEach((s) => s.close());
    child.stdin.end();
    await new Promise((resolve) => {
      child.once("exit", resolve);
      setTimeout(() => {
        child.kill();
        resolve();
      }, 4000).unref();
    });
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
