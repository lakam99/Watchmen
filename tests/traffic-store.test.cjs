const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");
const { TrafficStore, appIdentity } = require("../electron/traffic-store.cjs");
const START = Date.parse("2026-10-28T12:00:00Z");
function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "watchmen-profile-test-"));
  let now = START;
  const filename = path.join(dir, "traffic.sqlite");
  const stores = [];
  return {
    filename,
    get now() {
      return now;
    },
    advance(ms) {
      now += ms;
    },
    open(id) {
      const store = new TrafficStore(filename, {
        clock: () => now,
        sessionId: id,
      });
      stores.push(store);
      return store;
    },
    cleanup() {
      for (const store of stores) if (!store.closed) store.close();
      assert.equal(path.dirname(dir), os.tmpdir());
      assert.ok(path.basename(dir).startsWith("watchmen-profile-test-"));
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}
function flow(overrides = {}) {
  return {
    id: "socket-a",
    pid: 123,
    app: "Browser",
    processPath: "C:/Apps/Browser.exe",
    protocol: "TCP",
    localAddress: "192.168.1.1",
    localPort: 50000,
    remoteAddress: "8.8.8.8",
    remotePort: 443,
    state: "Established",
    active: true,
    received: 1000,
    sent: 100,
    rxRate: 1,
    txRate: 1,
    firstSeen: new Date(START).toISOString(),
    ...overrides,
  };
}
function snap(f, rows = [flow()], tracing = true) {
  return {
    timestamp: new Date(f.now).toISOString(),
    startedAt: new Date(START).toISOString(),
    tracing,
    eventsLost: 0,
    flows: rows,
  };
}
test("persistent byte totals use deltas and ignore duplicate or out-of-order snapshots", () => {
  const f = fixture();
  try {
    const store = f.open("one");
    store.ingest(snap(f));
    assert.equal(store.summary().totals.received, 0);
    f.advance(2000);
    store.ingest(snap(f, [flow({ received: 1300, sent: 140 })]));
    assert.equal(store.summary().totals.received, 300);
    assert.equal(store.summary().totals.sent, 40);
    assert.equal(store.summary().totals.observations, 1);
    store.ingest(snap(f, [flow({ received: 99999 })]), { force: true });
    assert.equal(store.summary().totals.received, 300);
    assert.equal(
      store.detail({ appId: appIdentity(flow()) }).endpoints[0].port,
      443,
    );
    assert.equal(
      store.summary({ search: "'; DROP TABLE applications; --" }).applications
        .length,
      0,
    );
    assert.throws(() => store.summary({ range: "garbage" }));
  } finally {
    f.cleanup();
  }
});
test("restarts retain the same application identity, daily history and location cache", () => {
  const f = fixture();
  try {
    let store = f.open("one");
    store.ingest(snap(f));
    f.advance(2000);
    store.ingest(snap(f, [flow({ received: 1200 })]));
    store.saveLocation("8.8.8.8", {
      country: "Test country",
      city: "Test city",
      org: "Test network",
    });
    store.close();
    store = f.open("two");
    const fresh = flow({
      pid: 456,
      id: "new-socket",
      processPath: "c:\\apps\\BROWSER.EXE",
      received: 0,
      sent: 0,
      firstSeen: new Date(f.now).toISOString(),
    });
    store.ingest(snap(f, [fresh]));
    f.advance(2000);
    store.ingest(snap(f, [{ ...fresh, received: 70, sent: 20 }]));
    const profile = store.summary();
    assert.equal(profile.totals.applications, 1);
    assert.equal(profile.totals.received, 270);
    assert.equal(profile.applications[0].sessions, 2);
    assert.equal(store.cachedLocations()["8.8.8.8"].country, "Test country");
    assert.equal(profile.countries[0].country, "Test country");
    assert.equal(profile.daily.length, 1);
    assert.equal(store.baseline([fresh])[0].sessions, 2);
  } finally {
    f.cleanup();
  }
});
test("overlapping instances elect one recorder and baseline on takeover without duplicate bytes", () => {
  const f = fixture();
  try {
    const a = f.open("a"),
      b = f.open("b");
    a.ingest(snap(f));
    assert.equal(b.ingest(snap(f, [flow({ received: 8000 })])), false);
    f.advance(2000);
    a.ingest(snap(f, [flow({ received: 1500 })]));
    assert.equal(b.ingest(snap(f, [flow({ received: 9000 })])), false);
    assert.equal(b.summary().totals.received, 500);
    assert.equal(b.summary().totals.sessions, 1);
    a.close();
    assert.equal(b.ingest(snap(f, [flow({ received: 9000 })])), true);
    assert.equal(b.summary().totals.received, 500);
    f.advance(2000);
    b.ingest(snap(f, [flow({ received: 9100 })]));
    assert.equal(b.summary().totals.received, 600);
    assert.equal(b.summary().totals.sessions, 2);
  } finally {
    f.cleanup();
  }
});
test("detailed capture preempts a standard recorder and counter resets never add old totals", () => {
  const f = fixture();
  try {
    const a = f.open("standard"),
      b = f.open("detailed");
    a.ingest(snap(f, undefined, false));
    assert.equal(b.ingest(snap(f, [flow({ received: 5000 })], true)), true);
    assert.equal(a.isRecorder(), false);
    f.advance(2000);
    assert.equal(a.ingest(snap(f, undefined, false)), false);
    b.ingest(snap(f, [flow({ received: 5300 })]));
    assert.equal(b.summary().totals.received, 300);
    f.advance(2000);
    b.ingest(snap(f, [flow({ received: 20 })]));
    assert.equal(b.summary().totals.received, 300);
    f.advance(2000);
    b.ingest(snap(f, [flow({ received: 50 })]));
    assert.equal(b.summary().totals.received, 330);
  } finally {
    f.cleanup();
  }
});
test("expired leases recover after a crash and ordinary mode records unknown byte coverage honestly", () => {
  const f = fixture();
  try {
    const a = f.open("old"),
      b = f.open("new");
    a.ingest(snap(f, undefined, false));
    f.advance(9000);
    b.ingest(snap(f, [flow({ received: 9000 })], false));
    f.advance(2000);
    b.ingest(snap(f, [flow({ received: 9500 })], false));
    const profile = b.summary();
    assert.equal(profile.totals.measuredMs, 0);
    assert.equal(profile.totals.received, 0);
    assert.equal(profile.totals.applications, 1);
    assert.equal(profile.totals.observations, 2);
    f.advance(2000);
    b.ingest(snap(f, [flow({ received: 0, sent: 0 })], false));
    f.advance(2000);
    b.ingest(
      snap(
        f,
        [flow({ received: 0, sent: 0, active: false, state: "Closed" })],
        false,
      ),
    );
    assert.equal(
      b.db
        .prepare("SELECT state FROM flow_cursors WHERE session_id='new'")
        .get().state,
      "Closed",
    );
    a.close();
    assert.equal(b.isRecorder(), true);
  } finally {
    f.cleanup();
  }
});
test("daily profiles survive raw cursor retention, and extra credential fields are not stored", () => {
  const f = fixture();
  try {
    let store = f.open("one");
    store.ingest(
      snap(f, [flow({ token: "synthetic-do-not-store-this-secret" })]),
    );
    f.advance(2000);
    store.ingest(snap(f, [flow({ received: 1300 })]));
    store.close();
    f.advance(31 * 86400000);
    store = f.open("two");
    store.ingest(
      snap(f, [
        flow({
          id: "new",
          remoteAddress: "1.1.1.1",
          firstSeen: new Date(f.now).toISOString(),
        }),
      ]),
    );
    assert.equal(store.summary().daily.length, 2);
    assert.equal(store.summary({ range: "7d" }).daily.length, 1);
    assert.equal(store.summary().totals.received, 300);
    assert.equal(
      store.db
        .prepare(
          "SELECT COUNT(*) count FROM flow_cursors WHERE session_id='one'",
        )
        .get().count,
      0,
    );
    store.close();
    assert.ok(
      !fs
        .readFileSync(f.filename)
        .includes(Buffer.from("synthetic-do-not-store-this-secret")),
    );
  } finally {
    f.cleanup();
  }
});
test("short-lived transfers between database flushes are retained after a socket closes", () => {
  const f = fixture();
  try {
    const store = f.open("one");
    store.ingest(snap(f, [], true));
    f.advance(2000);
    const short = flow({
      id: "short",
      active: false,
      state: "Closed",
      received: 400,
      sent: 90,
      rxRate: 0,
      txRate: 0,
      firstSeen: new Date(f.now - 500).toISOString(),
      lastSeen: new Date(f.now - 100).toISOString(),
    });
    store.ingest(snap(f, [short]));
    assert.equal(store.summary().totals.received, 400);
    assert.equal(store.summary().totals.observations, 1);
    f.advance(2000);
    store.ingest(snap(f, [short]));
    assert.equal(store.summary().totals.received, 400);
    assert.equal(store.summary().totals.observations, 1);
  } finally {
    f.cleanup();
  }
});
test("corrupt database files are preserved rather than replaced", () => {
  const f = fixture();
  try {
    const original = Buffer.from("synthetic-not-a-sqlite-database");
    fs.writeFileSync(f.filename, original);
    assert.throws(() => f.open("corrupt"));
    assert.deepEqual(fs.readFileSync(f.filename), original);
  } finally {
    f.cleanup();
  }
});
test("newer schemas are preserved rather than overwritten", () => {
  const f = fixture();
  try {
    const db = new DatabaseSync(f.filename);
    db.exec(
      "CREATE TABLE keep(value); INSERT INTO keep VALUES(42); PRAGMA user_version=99",
    );
    db.close();
    assert.throws(() => f.open("future"), /newer Watchmen/);
    const verify = new DatabaseSync(f.filename);
    assert.equal(verify.prepare("SELECT value FROM keep").get().value, 42);
    verify.close();
  } finally {
    f.cleanup();
  }
});
