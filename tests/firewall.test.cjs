const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { gzipSync } = require("node:zlib");
const { Firewall } = require("../electron/firewall.cjs");
const {
  Regions,
  countryCodes,
  ipNumber,
  rangeToCidrs,
} = require("../electron/regions.cjs");
const flow = {
  id: "test-flow",
  app: "Test Browser",
  processPath: "C:\\Apps\\Browser.exe",
  remoteAddress: "203.0.113.7",
  remotePort: 443,
  protocol: "TCP",
};
const blank = () => ({
  rules: [],
  admin: true,
  profiles: [
    { profile: 1, enabled: true },
    { profile: 2, enabled: true },
    { profile: 4, enabled: true },
  ],
  isolationVerified: true,
});
test("network rule previews derive executable and endpoint from trusted current flows", () => {
  const manager = new Firewall("unused", {
    snapshot: () => ({ admin: true, flows: [flow] }),
    transport: async () => blank(),
  });
  const preview = manager.prepare({
    kind: "connection",
    flowId: flow.id,
    appPath: "C:\\Other.exe",
    address: "8.8.8.8",
    port: 53,
  });
  assert.equal(preview.rule.appPath, flow.processPath);
  assert.equal(preview.rule.address, flow.remoteAddress);
  assert.equal(preview.rule.port, 443);
  assert.throws(
    () => manager.prepare({ kind: "app", flowId: "unknown" }),
    /no longer/,
  );
  assert.throws(
    () => manager.prepare({ kind: "delete-other-firewall-rules" }),
    /supported/,
  );
});
test("unattributed sockets can block an IP but cannot invent an executable or remote port", () => {
  const manager = new Firewall("unused", {
    snapshot: () => ({ flows: [{ ...flow, processPath: "", remotePort: 0 }] }),
    transport: async () => blank(),
  });
  assert.throws(
    () => manager.prepare({ kind: "app", flowId: flow.id }),
    /path is unavailable/,
  );
  assert.throws(
    () => manager.prepare({ kind: "connection", flowId: flow.id }),
    /path is unavailable/,
  );
  assert.equal(
    manager.prepare({ kind: "destination", flowId: flow.id }).rule.appPath,
    "",
  );
  const listener = new Firewall("unused", {
    snapshot: () => ({
      flows: [{ ...flow, remoteAddress: "*", remotePort: 0 }],
    }),
    transport: async () => blank(),
  });
  assert.throws(
    () => listener.prepare({ kind: "destination", flowId: flow.id }),
    /specific remote/,
  );
});
test("a reviewed rule is frozen and only known rule identifiers may be changed", async () => {
  let received;
  const manager = new Firewall("unused", {
    snapshot: () => ({ admin: true, flows: [flow] }),
    transport: async (request) => {
      received = request;
      return {
        ...blank(),
        rules: [{ ...request.rule, id: "saved-id", enabled: true }],
      };
    },
  });
  const preview = manager.prepare({ kind: "app", flowId: flow.id });
  preview.rule.appPath = "C:\\Injected.exe";
  await manager.apply(preview.id);
  assert.equal(received.rule.appPath, flow.processPath);
  assert.equal(manager.status().busy, false);
  await assert.rejects(() => manager.apply(preview.id), /expired/);
  await assert.rejects(() => manager.toggle("another-rule", false), /saved/);
  await assert.rejects(() => manager.forget("saved-id"), /Unblock/);
});
test("administrator access is required for all policy mutations", async () => {
  let writes = 0;
  const manager = new Firewall("unused", {
    snapshot: () => ({ admin: false, flows: [flow] }),
    transport: async () => {
      writes++;
      return blank();
    },
  });
  const preview = manager.prepare({ kind: "app", flowId: flow.id });
  await assert.rejects(() => manager.apply(preview.id), /administrator/);
  await assert.rejects(() => manager.unblockAll(), /administrator/);
  assert.equal(writes, 0);
});
test("concurrent mutation is refused and an operating-system error refreshes actual state", async () => {
  let release;
  const pending = new Promise((resolve) => (release = resolve));
  let calls = 0;
  const manager = new Firewall("unused", {
    snapshot: () => ({ admin: true, flows: [flow] }),
    transport: async (request) => {
      calls++;
      if (request.action === "list") return blank();
      await pending;
      throw new Error("Windows rejected the controlled rule.");
    },
  });
  const preview = manager.prepare({ kind: "app", flowId: flow.id });
  const applying = manager.apply(preview.id);
  await assert.rejects(() => manager.unblockAll(), /in progress/);
  release();
  await assert.rejects(() => applying, /rejected/);
  assert.equal(calls, 2);
  assert.equal(manager.status().busy, false);
  assert.deepEqual(manager.status().rules, []);
});
test("country selections reject unknown codes and IPv4/IPv6 ranges are converted exactly", () => {
  assert.deepEqual(countryCodes(["CA", "US", "CA"]), ["CA", "US"]);
  assert.throws(() => countryCodes(["../../policy"]), /region list/);
  assert.throws(() => countryCodes([]), /at least/);
  assert.deepEqual(
    rangeToCidrs(ipNumber("192.0.2.1").value, ipNumber("192.0.2.6").value, 32),
    ["192.0.2.1/32", "192.0.2.2/31", "192.0.2.4/31", "192.0.2.6/32"],
  );
  const a = ipNumber("2001:db8::"),
    b = ipNumber("2001:db8::ffff");
  assert.deepEqual(rangeToCidrs(a.value, b.value, a.bits), [
    "2001:db8:0:0:0:0:0:0/112",
  ]);
});
test("a cached monthly country dataset covers unseen IPv4 and IPv6 ranges without per-IP requests", async () => {
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), "watchmen-country-test-"),
  );
  try {
    await fs.writeFile(
      path.join(directory, "2026-10.csv.gz"),
      gzipSync(
        "192.0.2.0,192.0.2.127,CA\n192.0.2.128,192.0.2.255,CA\n198.51.100.0,198.51.100.255,US\n2001:db8::,2001:db8::ffff,CA\n",
      ),
    );
    let fetched = false;
    const regions = new Regions(directory, {
      clock: () => new Date("2026-10-28T12:00:00Z"),
      fetch: async () => {
        fetched = true;
        throw new Error("Unexpected request.");
      },
    });
    const prepared = await regions.prepare(["CA"]);
    assert.equal(fetched, false);
    assert.equal(prepared.ranges.length, 2);
    assert.equal(prepared.ranges[0], "192.0.2.0-192.0.2.255");
    assert.equal(
      prepared.ranges[1],
      "2001:db8:0:0:0:0:0:0-2001:db8:0:0:0:0:0:ffff",
    );
    assert.equal(prepared.sourceMonth, "2026-10");
    assert.ok(!prepared.ranges.some((r) => r.startsWith("198.51.100.")));
  } finally {
    assert.equal(path.dirname(directory), os.tmpdir());
    await fs.rm(directory, { recursive: true, force: true });
  }
});
test("malformed country caches are rejected and removed instead of creating broad blocks", async () => {
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), "watchmen-country-test-"),
  );
  try {
    const filename = path.join(directory, "2026-10.csv.gz");
    await fs.writeFile(filename, gzipSync("bad data\n"));
    const regions = new Regions(directory, {
      clock: () => new Date("2026-10-28T12:00:00Z"),
      fetch: async () => {
        throw new Error("Unexpected request.");
      },
    });
    await assert.rejects(() => regions.prepare(["CA"]), /format/);
    await assert.rejects(() => fs.access(filename));
  } finally {
    assert.equal(path.dirname(directory), os.tmpdir());
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test("region previews freeze the dated ranges before any Windows mutation", async () => {
  let admin = false,
    requests = [];
  const manager = new Firewall("unused", {
    snapshot: () => ({ admin, flows: [] }),
    transport: async (request) => {
      requests.push(request);
      return blank();
    },
  });
  let prepared = 0;
  manager.regions.prepare = async (countries) => {
    prepared++;
    return {
      countries,
      sourceMonth: "2026-10",
      rangeCount: 2,
      ranges: ["192.0.2.0-192.0.2.255", "2001:db8::1-2001:db8::ffff"],
    };
  };
  const preview = await manager.prepare({ kind: "region", countries: ["CA"] });
  assert.equal(preview.rule.rangeCount, 2);
  assert.equal(preview.rule.nativeRuleCount, 4);
  assert.equal(preview.rule.sourceMonth, "2026-10");
  assert.equal(preview.ranges, undefined);
  assert.equal(requests.length, 0);
  preview.rule.countries = ["US"];
  manager.regions.prepare = async () => {
    throw new Error("The dataset changed after review.");
  };
  admin = true;
  await manager.apply(preview.id);
  assert.deepEqual(requests[0].rule.countries, ["CA"]);
  assert.equal(requests[0].ranges.length, 2);
  assert.equal(prepared, 1);
  assert.equal(manager.status().busy, false);
});
