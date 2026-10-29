const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { parseCapture, decodeFrame } = require("../electron/packet-decode.cjs");
const { Packets } = require("../electron/packets.cjs");
const { frame, pcap, pcapng } = require("./packet-fixtures.cjs");
test("PCAP and PCAPNG decode readable HTTP with sensitive headers redacted", () => {
  const f = frame(
    "GET /watchmen?token=synthetic-secret HTTP/1.1\r\nAuthorization: Bearer synthetic-secret\r\nCookie: synthetic-secret\r\n\r\nhello",
  );
  for (const capture of [pcap([f]), pcapng([f])]) {
    const result = parseCapture(capture, {
      localAddresses: ["192.168.1.2"],
      flows: [
        {
          localAddress: "192.168.1.2",
          localPort: 50123,
          remoteAddress: "8.8.8.8",
          remotePort: 80,
          app: "Browser",
          pid: 123,
          protocol: "TCP",
        },
      ],
    });
    assert.equal(result.totalRecords, 1);
    const p = result.packets[0];
    assert.equal(p.protocol, "HTTP");
    assert.equal(p.direction, "Outgoing");
    assert.equal(p.app, "Browser");
    assert.ok(p.payloadText.includes("hello"));
    assert.ok(!p.payloadText.includes("synthetic-secret"));
    assert.ok(
      !p.hexHeaders.includes(Buffer.from("synthetic-secret").toString("hex")),
    );
    assert.ok(!p.summary.includes("synthetic-secret"));
  }
});
test("DNS questions are readable; secure-protocol payload is not falsely decrypted", () => {
  const dns = Buffer.concat([
    Buffer.from([0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
    Buffer.from([3]),
    Buffer.from("www"),
    Buffer.from([7]),
    Buffer.from("example"),
    Buffer.from([4]),
    Buffer.from("test"),
    Buffer.from([0, 0, 1, 0, 1]),
  ]);
  const d = decodeFrame(frame(dns, { udp: true }), {
    localAddresses: ["192.168.1.2"],
  });
  assert.equal(d.protocol, "DNS");
  assert.ok(d.payloadText.includes("www.example.test"));
  const tls = decodeFrame(
    frame(
      Buffer.concat([
        Buffer.from([23, 3, 3, 0, 12]),
        Buffer.from("opaque-bytes"),
      ]),
      { destinationPort: 443 },
    ),
  );
  assert.equal(tls.encrypted, true);
  assert.ok(!tls.payloadText.includes("opaque-bytes"));
});
test("malformed captures and packets are bounded and rejected safely", () => {
  assert.throws(() => parseCapture(Buffer.alloc(40)), /supported/);
  const broken = pcapng([frame("hello")]);
  broken.writeUInt32LE(999999, 28 + 20 + 20);
  assert.throws(() => parseCapture(broken));
  assert.equal(decodeFrame(Buffer.alloc(8)).protocol, "Truncated / malformed");
  const many = parseCapture(
    pcap(Array.from({ length: 510 }, () => frame("hello"))),
  );
  assert.equal(many.packets.length, 500);
  assert.equal(many.totalRecords, 510);
  assert.equal(many.limited, true);
});
test("capture manager streams readable packets and closes only its own helper", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "watchmen-packet-test-"));
  const { EventEmitter } = require("node:events");
  const { PassThrough } = require("node:stream");
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.stdin = new PassThrough();
  let ended = false;
  child.stdin.on("finish", () => {
    ended = true;
    child.emit("close", 0);
  });
  const manager = new Packets(dir, {
    snapshot: () => ({ admin: true }),
    agentPath: "test-helper",
    spawnAgent: (exe, args) => {
      assert.equal(exe, "test-helper");
      assert.deepEqual(args, ["--raw-packets", "5"]);
      setImmediate(() =>
        child.stdout.write(JSON.stringify({ type: "ready" }) + "\n"),
      );
      return child;
    },
  });
  try {
    await manager.start(5);
    child.stdout.write(
      JSON.stringify({
        type: "packet",
        data: frame("hello readable").subarray(14).toString("base64"),
        length: 100,
        timestamp: Date.now(),
      }) + "\n",
    );
    assert.equal(manager.status().active, true);
    assert.ok(manager.detail("1").payloadText.includes("hello readable"));
    assert.equal(manager.status().packets[0].payloadText, undefined);
    await manager.stop();
    assert.equal(ended, true);
    assert.equal(manager.status().active, false);
    assert.deepEqual(await fs.readdir(dir), []);
    await manager.shutdown();
    assert.equal(manager.status().packets.length, 0);
  } finally {
    assert.equal(path.dirname(dir), os.tmpdir());
    await fs.rm(dir, { recursive: true, force: true });
  }
});
test("PCAP import works without elevation and the original file is preserved", async () => {
  const dir = await fs.mkdtemp(
    path.join(os.tmpdir(), "watchmen-packet-import-"),
  );
  try {
    const filename = path.join(dir, "sample.pcap");
    await fs.writeFile(filename, pcap([frame("hello readable")]));
    const manager = new Packets(path.join(dir, "captures"), {
      snapshot: () => ({ admin: false }),
    });
    await assert.rejects(() => manager.start(5), /administrator/);
    const imported=await manager.importFile(filename);
    assert.equal(imported.processing,false);
    assert.equal(manager.status().totalRecords, 1);
    assert.ok(manager.detail("1").payloadText.includes("hello readable"));
    assert.equal(manager.status().packets[0].payloadText, undefined);
    await manager.shutdown();
    await fs.access(filename);
  } finally {
    assert.equal(path.dirname(dir), os.tmpdir());
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test("capture startup failure releases state and permits a later retry", async () => {
  const { EventEmitter } = require("node:events");
  const { PassThrough } = require("node:stream");
  const manager = new Packets(null, {
    snapshot: () => ({ admin: true }),
    agentPath: "test-helper",
    spawnAgent: () => {
      const child = new EventEmitter();
      child.stdin = new PassThrough();
      child.stdout = new PassThrough();
      child.stderr = new PassThrough();
      setImmediate(() => {
        child.emit("error", new Error("test launch failure"));
        child.emit("close", -1);
      });
      return child;
    },
  });
  await assert.rejects(() => manager.start(5), /could not be launched/);
  assert.equal(manager.status().active, false);
  assert.equal(manager.status().processing, false);
  await assert.rejects(() => manager.start(5), /could not be launched/);
  await manager.shutdown();
});

test("imported IPv6 TCP headers and plaintext are readable", () => {
  const ethernet = Buffer.alloc(14);
  ethernet.writeUInt16BE(0x86dd, 12);
  const payload = Buffer.from("IPv6 readable text");
  const ip = Buffer.alloc(40);
  ip[0] = 0x60;
  ip.writeUInt16BE(20 + payload.length, 4);
  ip[6] = 6;
  ip[7] = 64;
  ip.writeUInt16BE(0x2001, 8);
  ip.writeUInt16BE(0xdb8, 10);
  ip[23] = 1;
  ip.writeUInt16BE(0x2001, 24);
  ip.writeUInt16BE(0xdb8, 26);
  ip[39] = 2;
  const tcp = Buffer.alloc(20);
  tcp.writeUInt16BE(50123, 0);
  tcp.writeUInt16BE(80, 2);
  tcp[12] = 0x50;
  tcp[13] = 0x18;
  const result = parseCapture(
    pcapng([Buffer.concat([ethernet, ip, tcp, payload])]),
    { localAddresses: ["2001:db8::1"] },
  );
  assert.equal(result.packets[0].source, "2001:db8::1");
  assert.equal(result.packets[0].destination, "2001:db8::2");
  assert.equal(result.packets[0].direction, "Outgoing");
  assert.equal(result.packets[0].payloadText, "IPv6 readable text");
});
