const { test } = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { PassThrough, Writable } = require("node:stream");
const { nativeRequest, Firewall } = require("../electron/firewall.cjs");
const {
  exclusiveRanges,
  ipNumber,
  Regions,
} = require("../electron/regions.cjs");
const fs = require("node:fs/promises"),
  os = require("node:os"),
  path = require("node:path");
const { gzipSync } = require("node:zlib");
const blank = () => ({ rules: [], admin: true, isolationVerified: true });
function fakeChild(run) {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  let input = "";
  child.stdin = new Writable({
    write(chunk, _, done) {
      input += chunk.toString();
      done();
      run(child, input);
    },
  });
  child.kill = () => {
    child.killed = true;
    child.emit("close", 1);
  };
  return child;
}
test("native transport reads chunked progress, keeps the control channel open and waits for final commit", async () => {
  let child,
    closed = false;
  const progress = [];
  const result = nativeRequest(
    "fixture",
    { action: "add" },
    {
      onProgress: (p) => progress.push(p),
      spawnHelper: () =>
        (child = fakeChild((c, input) => {
          assert.equal(JSON.parse(input).control, true);
          queueMicrotask(() => {
            c.stdout.write('{"type":"pro');
            c.stdout.write(
              'gress","stage":"staging","completed":1,"total":2}\n',
            );
            c.stdout.write(
              '{"type":"progress","stage":"committing","canCancel":false}\n',
            );
            setTimeout(() => {
              c.stdout.write(
                JSON.stringify({ ok: true, value: blank() }) + "\n",
              );
              closed = true;
              c.emit("close", 0);
            }, 15);
          });
        })),
    },
  );
  assert.equal(closed, false);
  assert.equal(child.stdin.writableEnded, false);
  assert.equal((await result).isolationVerified, true);
  assert.equal(progress.length, 2);
  assert.equal(closed, true);
});
test("native cancellation is requested over stdin and acknowledged after rollback", async () => {
  const controller = new AbortController();
  let child;
  const result = nativeRequest(
    "fixture",
    { action: "add" },
    {
      signal: controller.signal,
      onProgress: () => {},
      spawnHelper: () =>
        (child = fakeChild((c, input) => {
          if (input.endsWith("cancel\n"))
            queueMicrotask(() => {
              c.stdout.write(
                '{"ok":false,"cancelled":true,"error":"rolled back"}\n',
              );
              c.emit("close", 2);
            });
        })),
    },
  );
  controller.abort();
  await assert.rejects(result, (e) => e.cancelled === true);
  assert.equal(child.killed, undefined);
});
test("silent native helper times out without claiming rollback or enforcement", async () => {
  const promise = nativeRequest(
    "fixture",
    { action: "add" },
    {
      onProgress: () => {},
      idleMs: 15,
      spawnHelper: () => fakeChild(() => {}),
    },
  );
  await assert.rejects(
    promise,
    (e) => e.verificationNeeded && /verify committed/.test(e.message),
  );
});
test("job progress remains available while mutation is pending; cancellation settles busy state", async () => {
  let options, release;
  const manager = new Firewall("unused", {
    snapshot: () => ({
      admin: true,
      flows: [{ id: "f", app: "App", processPath: "C:\\App.exe" }],
    }),
    transport: async (request, o) => {
      if (request.action === "list") return blank();
      options = o;
      return new Promise((resolve, reject) => {
        release = () => resolve(blank());
        o.signal.addEventListener("abort", () => {
          const e = new Error("Cancelled after rollback");
          e.cancelled = true;
          reject(e);
        });
      });
    },
  });
  const preview = manager.prepare({ kind: "app", flowId: "f" }),
    pending = manager.apply(preview.id);
  options.onProgress({
    stage: "staging",
    message: "Staging",
    completed: 32,
    total: 64,
    canCancel: true,
    lastAdvancedAt: new Date().toISOString(),
  });
  assert.equal(manager.status().job.completed, 32);
  assert.equal(manager.status().busy, true);
  manager.cancel();
  await assert.rejects(pending, /Cancelled/);
  assert.equal(manager.status().busy, false);
  assert.equal(manager.status().job.status, "cancelled");
  const done = manager.apply(preview.id);
  release();
  await done;
  assert.equal(manager.status().job.status, "completed");
  assert.equal(manager.status().busy, false);
});
function contains(ranges, ip) {
  const n = ipNumber(ip);
  return ranges.some((range) => {
    const [a, b] = range.split("-"),
      first = ipNumber(a),
      last = ipNumber(b || a);
    return (
      n.bits === first.bits && n.value >= first.value && n.value <= last.value
    );
  });
}
test("country-only complement covers unknown space and exact boundaries in IPv4 and IPv6", () => {
  const ranges = exclusiveRanges(
    ["24.0.0.0-24.255.255.255", "2001:db8::1-2001:db8::ffff"],
    { allowLocalNetwork: false },
  );
  for (const ip of [
    "23.255.255.255",
    "25.0.0.0",
    "0.0.0.0",
    "255.255.255.255",
    "2001:db8::",
    "2001:db8::1:0",
    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
  ])
    assert.equal(contains(ranges, ip), true, ip);
  for (const ip of [
    "24.0.0.0",
    "24.255.255.255",
    "2001:db8::1",
    "2001:db8::ffff",
  ])
    assert.equal(contains(ranges, ip), false, ip);
  const local = exclusiveRanges(["24.0.0.0-24.255.255.255"]);
  for (const ip of [
    "127.0.0.1",
    "10.0.0.1",
    "172.16.0.1",
    "192.168.1.1",
    "169.254.0.1",
    "100.64.0.1",
    "::1",
    "fc00::1",
    "fe80::1",
    "ff02::1",
  ])
    assert.equal(contains(local, ip), false, ip);
  assert.equal(contains(local, "8.8.8.8"), true);
});
test("country-only dataset includes Canada and US, with explicit unknown and local exemptions", async () => {
  const directory = await fs.mkdtemp(
    path.join(os.tmpdir(), "watchmen-exclusive-"),
  );
  try {
    await fs.writeFile(
      path.join(directory, "2026-10.csv.gz"),
      gzipSync(
        "24.0.0.0,24.255.255.255,CA\n25.0.0.0,25.255.255.255,US\n26.0.0.0,26.255.255.255,FR\n27.0.0.0,27.255.255.255,ZZ\n2001:db8::1,2001:db8::ffff,CA\n2001:db9::1,2001:db9::ffff,FR\n",
      ),
    );
    const regions = new Regions(directory, {
      clock: () => new Date("2026-10-28"),
      fetch: () => {
        throw new Error("Should use cache");
      },
    });
    const strict = await regions.prepare(["CA", "US"], { exclusive: true });
    assert.equal(contains(strict.ranges, "24.1.1.1"), false);
    assert.equal(contains(strict.ranges, "25.1.1.1"), false);
    assert.equal(contains(strict.ranges, "26.1.1.1"), true);
    assert.equal(contains(strict.ranges, "27.1.1.1"), true);
    assert.equal(contains(strict.ranges, "8.8.8.8"), true);
    assert.equal(contains(strict.ranges, "2001:db9::1"), true);
    const relaxed = await regions.prepare(["CA", "US"], {
      exclusive: true,
      allowUnknown: true,
    });
    assert.equal(contains(relaxed.ranges, "26.1.1.1"), true);
    assert.equal(contains(relaxed.ranges, "27.1.1.1"), false);
    assert.equal(contains(relaxed.ranges, "8.8.8.8"), false);
    const manager = new Firewall(directory, {
      snapshot: () => ({ admin: true }),
      transport: async (request) => {
        assert.equal(request.rule.allowUnknown, false);
        assert.equal(request.rule.allowLocalNetwork, true);
        assert.equal(request.rule.kind, "onlyRegion");
        return blank();
      },
    });
    manager.regions = regions;
    const review = await manager.prepare({
      kind: "onlyRegion",
      countries: ["CA", "US"],
    });
    review.rule.allowUnknown = true;
    await manager.apply(review.id);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});
