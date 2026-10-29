const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { stripTypeScriptTypes } = require("node:module");
const context = {};
const code = stripTypeScriptTypes(
  fs.readFileSync("src/model.ts", "utf8"),
).replace(/^export /gm, "");
vm.runInNewContext(
  code + ";globalThis.model={scope,groupFlows,bytes};",
  context,
);
const { scope, groupFlows, bytes } = context.model;
const { isPublicIP } = require("../electron/network.cjs");
test("local and listening addresses are classified without sending private IPs for lookup", () => {
  for (const ip of [
    "127.0.0.1",
    "10.1.2.3",
    "172.16.0.1",
    "172.31.255.3",
    "192.168.4.1",
    "169.254.0.1",
    "100.64.0.1",
    "::1",
    "fe80::1",
    "fc00::1",
    "::ffff:192.168.1.1",
  ]) {
    assert.equal(scope(ip), "local", ip);
    assert.equal(isPublicIP(ip), false, ip);
  }
  for (const ip of ["*", "0.0.0.0", "::"]) {
    assert.equal(scope(ip), "listener");
    assert.equal(isPublicIP(ip), false);
  }
  for (const ip of ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"]) {
    assert.equal(scope(ip), "internet");
    assert.equal(isPublicIP(ip), true);
  }
  for (const ip of [
    "2001:db8::1",
    "203.0.113.1",
    "198.51.100.1",
    "224.0.0.1",
    "garbage",
  ])
    assert.equal(isPublicIP(ip), false);
});
const base = {
  app: "Browser",
  processPath: "C:/browser.exe",
  pid: 22,
  protocol: "TCP",
  localAddress: "10.0.0.1",
  localPort: 123,
  remoteAddress: "1.1.1.1",
  remotePort: 443,
  active: true,
  received: 120,
  sent: 40,
  rxRate: 30,
  txRate: 10,
};
test("aggregation preserves bidirectional totals and merges processes by executable", () => {
  const f = [
    base,
    { ...base, pid: 23, remoteAddress: "8.8.8.8", received: 80, sent: 60 },
  ];
  const groups = groupFlows(f, "app", {});
  assert.equal(groups.length, 1);
  assert.equal(groups[0].received, 200);
  assert.equal(groups[0].sent, 100);
  assert.equal(groups[0].rxRate, 60);
  assert.equal(groups[0].flows.length, 2);
  assert.equal(groups[0].subtitle, "2 processes · 2 destinations");
  assert.equal(
    groupFlows([...f, { ...base, processPath: "C:/other.exe" }], "app", {})
      .length,
    2,
  );
});
test("country grouping preserves unknown, local and listening distinctions", () => {
  const groups = groupFlows(
    [
      base,
      { ...base, remoteAddress: "8.8.8.8" },
      { ...base, remoteAddress: "192.168.0.1" },
      { ...base, remoteAddress: "*" },
    ],
    "country",
    { "1.1.1.1": { country: "Australia" } },
  );
  assert.deepEqual(
    Array.from(groups, (g) => g.name),
    ["Australia", "Unresolved", "Local network", "Listening endpoints"],
  );
});
test("formatting handles zeros, binary units, and invalid measurements", () => {
  assert.equal(bytes(0, true), "0 B/s");
  assert.equal(bytes(1024), "1.0 KB");
  assert.equal(bytes(1024 * 1024, true), "1.0 MB/s");
  assert.equal(bytes(NaN), "—");
  assert.equal(bytes(-1), "—");
});
