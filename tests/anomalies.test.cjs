const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { TrafficStore, appIdentity } = require("../electron/traffic-store.cjs");
const { Insights } = require("../electron/insights.cjs");
const START = Date.parse("2026-10-28T12:00:00Z");
function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "watchmen-alert-test-"));
  let now = START;
  const store = new TrafficStore(path.join(dir, "traffic.sqlite"), {
    clock: () => now,
    sessionId: "test",
  });
  const flow = {
    id: "base",
    pid: 1,
    app: "Browser",
    processPath: "C:/Browser.exe",
    protocol: "TCP",
    remoteAddress: "8.8.8.8",
    remotePort: 443,
    localAddress: "192.168.1.2",
    localPort: 50123,
    active: true,
    state: "Established",
    firstSeen: new Date(START).toISOString(),
    received: 0,
    sent: 0,
  };
  return {
    store,
    flow,
    get now() {
      return now;
    },
    advance(ms) {
      now += ms;
    },
    ingest(rows = [flow], tracing = false) {
      return store.ingest({
        timestamp: new Date(now).toISOString(),
        startedAt: new Date(START).toISOString(),
        tracing,
        eventsLost: 0,
        flows: rows,
      });
    },
    warm() {
      this.ingest();
      for (let i = 0; i < 60; i++) {
        now += 2000;
        this.ingest();
      }
    },
    cleanup() {
      store.close();
      assert.equal(path.dirname(dir), os.tmpdir());
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}
test("new destinations and services use the pre-change baseline after learning, and do not repeat", () => {
  const f = fixture();
  try {
    f.ingest();
    f.advance(2000);
    f.ingest([{ ...f.flow, id: "cold", remoteAddress: "1.1.1.1" }]);
    assert.equal(f.store.anomalies.list().alerts.length, 0);
    f.warm();
    f.advance(2000);
    f.ingest([
      {
        ...f.flow,
        id: "new",
        remoteAddress: "9.9.9.9",
        firstSeen: new Date(f.now).toISOString(),
      },
    ]);
    let alerts = f.store.anomalies.list().alerts;
    assert.equal(alerts.filter((a) => a.type === "new_destination").length, 1);
    assert.equal(alerts[0].evidence.baseline.knownDestinations, 2);
    assert.ok(
      f.store
        .detail({ appId: appIdentity(f.flow) })
        .endpoints.some((e) => e.address === "9.9.9.9"),
    );
    f.advance(2000);
    f.ingest([{ ...f.flow, id: "new-service", remotePort: 8443 }]);
    assert.equal(
      f.store.anomalies.list().alerts.filter((a) => a.type === "new_service")
        .length,
      1,
    );
    f.advance(2000);
    f.ingest([{ ...f.flow, id: "new-service", remotePort: 8443 }]);
    assert.equal(
      f.store.anomalies.list().alerts.filter((a) => a.type === "new_service")
        .length,
      1,
    );
  } finally {
    f.cleanup();
  }
});
test("dismissal is persistent and the AI preview omits the destination unless opted in", async () => {
  const f = fixture();
  try {
    f.warm();
    f.advance(2000);
    f.ingest([{ ...f.flow, id: "new", remoteAddress: "1.1.1.1" }]);
    const alert = f.store.anomalies.list().alerts[0];
    const change = f.store.anomalies.explainPayload(alert.id);
    assert.equal(change.evidence.observed.address, undefined);
    assert.equal(
      f.store.anomalies.explainPayload(alert.id, true).evidence.observed
        .address,
      "1.1.1.1",
    );
    f.store.anomalies.setStatus(alert.id, "dismissed");
    assert.equal(f.store.anomalies.list().alerts.length, 0);
    assert.equal(
      f.store.anomalies.list({ status: "dismissed" }).alerts.length,
      1,
    );
    const ai = new Insights(
      {
        credential: async () => ({
          provider: "openrouter",
          baseUrl: "https://openrouter.ai/api/v1",
          model: "mock",
          token: "synthetic-key",
        }),
      },
      async (_url, options) => {
        const body = JSON.parse(options.body);
        assert.ok(body.messages[1].content.includes("traffic_change"));
        assert.ok(!body.messages[1].content.includes("1.1.1.1"));
        return new Response(
          JSON.stringify({
            choices: [
              {
                message: {
                  content: "The destination changed from the saved baseline.",
                },
              },
            ],
          }),
        );
      },
    );
    const reply = await ai.run(ai.prepareChange(change).id);
    assert.equal(reply.alertId, alert.id);
    f.store.anomalies.saveExplanation(reply.alertId, reply);
    assert.ok(
      f.store.anomalies
        .list({ status: "all" })
        .alerts[0].explanation.text.includes("destination changed"),
    );
  } finally {
    f.cleanup();
  }
});
test("new resolved countries are changes only when a previous location baseline exists", () => {
  const f = fixture();
  try {
    f.warm();
    f.store.saveLocation("8.8.8.8", { country: "Country A" });
    assert.equal(
      f.store.anomalies.list().alerts.filter((a) => a.type === "new_country")
        .length,
      0,
    );
    f.advance(2000);
    f.ingest([{ ...f.flow, id: "new", remoteAddress: "1.1.1.1" }]);
    f.store.saveLocation("1.1.1.1", { country: "Country B" });
    const alerts = f.store.anomalies
      .list()
      .alerts.filter((a) => a.type === "new_country");
    assert.equal(alerts.length, 1);
    assert.deepEqual(alerts[0].evidence.baseline.knownCountries, ["Country A"]);
    f.store.saveLocation("1.1.1.1", { country: "Country B" });
    assert.equal(
      f.store.anomalies.list().alerts.filter((a) => a.type === "new_country")
        .length,
      1,
    );
  } finally {
    f.cleanup();
  }
});
test("sustained traffic spikes require measured coverage, sufficient baseline, volume floor and cooldown", () => {
  const f = fixture();
  try {
    f.ingest();
    const id = appIdentity(f.flow);
    f.advance(8 * 60000);
    const minute = Math.floor(f.now / 60000) * 60000;
    for (let i = 1; i <= 6; i++)
      f.store
        .q("INSERT INTO rate_windows VALUES(?,?,?,?,?,1)")
        .run(
          id,
          minute - i * 60000,
          i === 1 ? 20 * 1024 * 1024 : 60000,
          0,
          60000,
        );
    const app = { id, name: "Browser", received: 1000, sent: 0 };
    const input = {
      apps: new Map([[id, app]]),
      edges: new Map(),
      timestamp: f.now,
      measured: false,
      elapsed: 2000,
    };
    f.store.anomalies.observe(input);
    assert.equal(f.store.anomalies.list().alerts.length, 0);
    f.store.anomalies.observe({ ...input, measured: true });
    const spikes = f.store.anomalies.list().alerts;
    assert.equal(spikes.length, 1);
    assert.equal(spikes[0].type, "traffic_spike");
    assert.equal(spikes[0].evidence.baseline.windows, 5);
    assert.ok(spikes[0].evidence.observed.bytesPerSecond > 128 * 1024);
    f.store.anomalies.observe({ ...input, measured: true });
    assert.equal(f.store.anomalies.list().alerts.length, 1);
  } finally {
    f.cleanup();
  }
});
test("bad-quality or poorly covered windows cannot trigger a spike", () => {
  const f = fixture();
  try {
    f.ingest();
    const id = appIdentity(f.flow);
    f.advance(8 * 60000);
    const minute = Math.floor(f.now / 60000) * 60000;
    for (let i = 1; i <= 6; i++)
      f.store
        .q("INSERT INTO rate_windows VALUES(?,?,?,?,?,?)")
        .run(
          id,
          minute - i * 60000,
          i === 1 ? 20 * 1024 * 1024 : 60000,
          0,
          i === 1 ? 20000 : 60000,
          i === 1 ? 0 : 1,
        );
    f.store.anomalies.observe({
      apps: new Map([[id, { id, name: "Browser", received: 100, sent: 0 }]]),
      edges: new Map(),
      timestamp: f.now,
      measured: true,
      elapsed: 2000,
    });
    assert.equal(f.store.anomalies.list().alerts.length, 0);
  } finally {
    f.cleanup();
  }
});

test("browser destination churn creates one review group; repeated snapshots cannot inflate it", () => {
  const f = fixture();
  try {
    f.warm();
    for (let i = 1; i <= 80; i++) {
      f.advance(2000);
      f.ingest([
        { ...f.flow, id: "new-" + i, remoteAddress: "203.0.113." + i },
      ]);
    }
    let feed = f.store.anomalies.list();
    assert.equal(feed.counts.open, 1);
    assert.equal(f.store.anomalies.openCount(), 1);
    assert.equal(feed.alerts[0].occurrences, 80);
    assert.equal(feed.alerts[0].evidence.activity.recent.length, 20);
    const original = feed.alerts[0].evidence.baseline.knownDestinations;
    for (let i = 0; i < 5; i++) {
      f.advance(2000);
      f.ingest([{ ...f.flow, id: "new-80", remoteAddress: "203.0.113.80" }]);
    }
    feed = f.store.anomalies.list();
    assert.equal(feed.alerts[0].occurrences, 80);
    assert.equal(feed.alerts[0].evidence.baseline.knownDestinations, original);
    assert.ok(
      !JSON.stringify(
        f.store.anomalies.explainPayload(feed.alerts[0].id),
      ).includes("203.0.113."),
    );
    f.store.anomalies.dismissAll();
    assert.equal(f.store.anomalies.openCount(), 0);
    f.advance(2000);
    f.ingest([{ ...f.flow, id: "new-80", remoteAddress: "203.0.113.80" }]);
    assert.equal(f.store.anomalies.openCount(), 0);
  } finally {
    f.cleanup();
  }
});
test("temporary remote ports stay profiled without producing service notices", () => {
  const f = fixture();
  try {
    f.warm();
    for (let i = 49152; i < 49252; i++) {
      f.advance(2000);
      f.ingest([{ ...f.flow, id: "port-" + i, remotePort: i }]);
    }
    assert.equal(
      f.store.anomalies.list().alerts.filter((a) => a.type === "new_service")
        .length,
      0,
    );
    assert.equal(
      f.store.q("SELECT COUNT(*) count FROM edges WHERE port>=49152").get()
        .count,
      100,
    );
    f.advance(2000);
    f.ingest([{ ...f.flow, id: "service", remotePort: 8443 }]);
    assert.equal(
      f.store.anomalies.list().alerts.filter((a) => a.type === "new_service")
        .length,
      1,
    );
  } finally {
    f.cleanup();
  }
});
test("stale notices leave the open badge after 24 hours and retain reviewed history and baseline", () => {
  const f = fixture();
  try {
    f.warm();
    f.advance(2000);
    f.ingest([{ ...f.flow, id: "new", remoteAddress: "1.1.1.1" }]);
    assert.equal(f.store.anomalies.openCount(), 1);
    f.advance(24 * 60 * 60000 + 1);
    assert.equal(f.store.anomalies.openCount(), 0);
    assert.equal(f.store.anomalies.list().alerts.length, 0);
    assert.equal(
      f.store.anomalies.list({ status: "archived" }).alerts.length,
      1,
    );
    assert.ok(f.store.q("SELECT 1 FROM edges WHERE address='1.1.1.1'").get());
  } finally {
    f.cleanup();
  }
});
test("old per-endpoint alerts collapse during migration without losing source records", () => {
  const f = fixture();
  try {
    f.warm();
    const appId = appIdentity(f.flow);
    for (let i = 0; i < 6; i++)
      f.store
        .q(
          "INSERT INTO alerts(id,dedupe_key,type,app_id,app_name,address,severity,observed_at,evidence_json) VALUES(?,?,?,?,?,?,?,?,?)",
        )
        .run(
          "legacy-" + i,
          "legacy-key-" + i,
          "new_destination",
          appId,
          "Browser",
          "203.0.113." + i,
          "notice",
          f.now,
          JSON.stringify({
            baseline: { knownDestinations: 1 },
            observed: { address: "203.0.113." + i },
            note: "Fixture",
          }),
        );
    f.store
      .q("DELETE FROM detector_migrations WHERE name='grouped_changes_v1'")
      .run();
    f.store.anomalies.initialize();
    assert.equal(f.store.anomalies.openCount(), 1);
    assert.equal(f.store.anomalies.list().alerts[0].occurrences, 6);
    assert.equal(
      f.store
        .q("SELECT COUNT(*) count FROM alerts WHERE id LIKE 'legacy-%'")
        .get().count,
      6,
    );
    f.store.anomalies.setStatus(
      f.store.anomalies.list().alerts[0].id,
      "dismissed",
    );
    assert.equal(f.store.anomalies.openCount(), 0);
  } finally {
    f.cleanup();
  }
});
