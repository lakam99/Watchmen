const { randomUUID } = require("node:crypto");
const MINUTE = 60000,
  DAY = 86400000,
  LEARN_MS = 120000;
const median = (values) => {
  const sorted = values.slice().sort((a, b) => a - b);
  return sorted.length % 2
    ? sorted[(sorted.length - 1) / 2]
    : (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2;
};
class Anomalies {
  constructor(store) {
    this.store = store;
    this.q = (sql) => store.q(sql);
  }
  initialize() {
    this.store.db.exec(`
 CREATE TABLE IF NOT EXISTS detector_meta(id INTEGER PRIMARY KEY CHECK(id=1),enabled_at INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS app_countries(app_id TEXT NOT NULL,country TEXT NOT NULL,first_seen INTEGER NOT NULL,PRIMARY KEY(app_id,country));
 CREATE TABLE IF NOT EXISTS rate_windows(app_id TEXT NOT NULL,minute INTEGER NOT NULL,received INTEGER NOT NULL DEFAULT 0,sent INTEGER NOT NULL DEFAULT 0,measured_ms INTEGER NOT NULL DEFAULT 0,quality_ok INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(app_id,minute));
 CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY,dedupe_key TEXT NOT NULL UNIQUE,type TEXT NOT NULL,app_id TEXT NOT NULL,app_name TEXT NOT NULL,address TEXT NOT NULL DEFAULT '',severity TEXT NOT NULL,observed_at INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'open',evidence_json TEXT NOT NULL,explanation_json TEXT);
 CREATE INDEX IF NOT EXISTS alerts_feed ON alerts(status,observed_at);
 CREATE INDEX IF NOT EXISTS rates_age ON rate_windows(minute);
 `);
    this.q("INSERT OR IGNORE INTO detector_meta VALUES(1,?)").run(
      this.store.clock(),
    );
    this.store.db.exec(
      "INSERT OR IGNORE INTO app_countries SELECT e.app_id,d.country,MIN(e.first_seen) FROM edges e JOIN destinations d ON d.address=e.address WHERE d.country!='' GROUP BY e.app_id,d.country;",
    );
  }
  maturity(appId) {
    return this.q(
      "SELECT COALESCE(SUM(observed_ms),0) observedMs,COALESCE(SUM(observations),0) observations FROM app_daily WHERE app_id=?",
    ).get(appId);
  }
  add(
    type,
    appId,
    appName,
    address,
    key,
    evidence,
    timestamp,
    severity = "notice",
  ) {
    this.q(
      "INSERT OR IGNORE INTO alerts(id,dedupe_key,type,app_id,app_name,address,severity,observed_at,evidence_json) VALUES(?,?,?,?,?,?,?,?,?)",
    ).run(
      randomUUID(),
      key,
      type,
      appId,
      appName,
      address,
      severity,
      timestamp,
      JSON.stringify({ version: 1, ...evidence }),
    );
  }
  observe({ apps, edges, timestamp, measured, elapsed, quality = true }) {
    const maturity = new Map();
    for (const app of apps.values())
      maturity.set(app.id, this.maturity(app.id));
    for (const edge of edges.values()) {
      if (
        edge.address === "*" ||
        edge.port === 0 ||
        edge.address === "::1" ||
        edge.address.startsWith("127.") ||
        edge.address.startsWith("::ffff:127.")
      )
        continue;
      const base = maturity.get(edge.appId);
      if (!base || base.observedMs < LEARN_MS) continue;
      const app = apps.get(edge.appId),
        known = this.q(
          "SELECT COUNT(DISTINCT address) count FROM edges WHERE app_id=? AND port>0",
        ).get(edge.appId).count;
      if (
        !this.q("SELECT 1 FROM edges WHERE app_id=? AND address=? LIMIT 1").get(
          edge.appId,
          edge.address,
        )
      )
        this.add(
          "new_destination",
          edge.appId,
          app.name,
          edge.address,
          "destination:" + edge.appId + ":" + edge.address,
          {
            summary: "First recorded destination IP for this application.",
            baseline: { knownDestinations: known, observedMs: base.observedMs },
            observed: {
              address: edge.address,
              protocol: edge.protocol,
              port: edge.port,
            },
            note: "CDNs, updates, VPNs, and ordinary browsing can introduce new IPs. This is a change notice, not a threat verdict.",
          },
          timestamp,
        );
      if (
        !this.q(
          "SELECT 1 FROM edges WHERE app_id=? AND protocol=? AND port=? LIMIT 1",
        ).get(edge.appId, edge.protocol, edge.port)
      ) {
        const ports = this.q(
          "SELECT protocol,port,SUM(observations) observations FROM edges WHERE app_id=? AND port>0 GROUP BY protocol,port ORDER BY observations DESC LIMIT 12",
        ).all(edge.appId);
        this.add(
          "new_service",
          edge.appId,
          app.name,
          edge.address,
          `service:${edge.appId}:${edge.protocol}:${edge.port}`,
          {
            summary:
              "A remote protocol/port combination not previously observed for this app.",
            baseline: { usualServices: ports, observedMs: base.observedMs },
            observed: {
              address: edge.address,
              protocol: edge.protocol,
              port: edge.port,
            },
            note: "A new service is unusual relative to recorded history; the port alone does not identify the application protocol or prove risk.",
          },
          timestamp,
          "review",
        );
      }
    }
    const minute = Math.floor(timestamp / MINUTE) * MINUTE;
    for (const app of apps.values()) {
      if (!measured || elapsed <= 0) continue;
      this.q(
        "INSERT INTO rate_windows VALUES(?,?,?,?,?,?) ON CONFLICT(app_id,minute) DO UPDATE SET received=received+excluded.received,sent=sent+excluded.sent,measured_ms=measured_ms+excluded.measured_ms,quality_ok=MIN(quality_ok,excluded.quality_ok)",
      ).run(
        app.id,
        minute,
        app.received,
        app.sent,
        elapsed,
        quality && !app.counterReset ? 1 : 0,
      );
      const windows = this.q(
        "SELECT * FROM rate_windows WHERE app_id=? AND minute<? AND minute>=? AND measured_ms>=30000 AND quality_ok=1 ORDER BY minute DESC LIMIT 31",
      ).all(app.id, minute, timestamp - DAY);
      if (windows.length < 6) continue;
      const current = windows[0],
        baseline = windows.slice(1);
      if (current.minute < minute - 2 * MINUTE) continue;
      for (const direction of ["received", "sent"]) {
        const rates = baseline.map(
            (w) => w[direction] / (w.measured_ms / 1000),
          ),
          center = median(rates),
          mad = median(rates.map((v) => Math.abs(v - center))),
          rate = current[direction] / (current.measured_ms / 1000),
          threshold = Math.max(128 * 1024, center * 5, center + 6 * mad);
        if (rate < threshold || current[direction] < 4 * 1024 * 1024) continue;
        this.add(
          "traffic_spike",
          app.id,
          app.name,
          "",
          `spike:${app.id}:${direction}:${Math.floor(current.minute / (10 * MINUTE))}`,
          {
            summary: `Sustained ${direction === "received" ? "download" : "upload"} rate above the measured baseline.`,
            baseline: {
              direction,
              medianBytesPerSecond: center,
              medianAbsoluteDeviation: mad,
              thresholdBytesPerSecond: threshold,
              windows: baseline.length,
              windowSeconds: 60,
            },
            observed: {
              windowStart: current.minute,
              measuredMs: current.measured_ms,
              bytes: current[direction],
              bytesPerSecond: rate,
              ratio: center > 0 ? rate / center : null,
            },
            note: "Requires five earlier completed measured minutes and at least 30 seconds of coverage per minute. Floors: 128 KB/s and 4 MB. One notice per app/direction per 10-minute bucket. A spike can be a legitimate update or transfer.",
          },
          current.minute + MINUTE,
          "review",
        );
      }
    }
    this.q("DELETE FROM rate_windows WHERE minute<?").run(timestamp - 7 * DAY);
  }
  location(address, timestamp) {
    const destination = this.q(
      "SELECT country,lookup_at FROM destinations WHERE address=?",
    ).get(address);
    if (!destination?.country) return;
    const enabled = this.q(
      "SELECT enabled_at FROM detector_meta WHERE id=1",
    ).get().enabled_at;
    const apps = this.q(
      "SELECT DISTINCT a.id,a.name,MIN(e.first_seen) firstSeen,MAX(e.last_seen) lastSeen FROM edges e JOIN applications a ON a.id=e.app_id WHERE e.address=? GROUP BY a.id",
    ).all(address);
    for (const app of apps) {
      const prior = this.q(
        "SELECT country FROM app_countries WHERE app_id=? ORDER BY country",
      )
        .all(app.id)
        .map((row) => row.country);
      const isNew = !prior.includes(destination.country);
      if (
        isNew &&
        prior.length &&
        app.firstSeen >= enabled &&
        app.lastSeen >= timestamp - 5 * MINUTE &&
        this.maturity(app.id).observedMs >= LEARN_MS
      )
        this.add(
          "new_country",
          app.id,
          app.name,
          address,
          "country:" + app.id + ":" + destination.country,
          {
            summary:
              "A recently observed destination resolved to a country not in this app’s saved location history.",
            baseline: { knownCountries: prior.slice(0, 20) },
            observed: {
              address,
              country: destination.country,
              lookupAt: destination.lookup_at,
            },
            note: "IP location is approximate and may reflect a CDN, VPN, proxy, anycast routing, or changed lookup data. This does not establish where a person or service actually is.",
          },
          timestamp,
        );
      this.q("INSERT OR IGNORE INTO app_countries VALUES(?,?,?)").run(
        app.id,
        destination.country,
        timestamp,
      );
    }
  }
  row(row) {
    return {
      ...row,
      evidence: JSON.parse(row.evidence_json),
      explanation: row.explanation_json
        ? JSON.parse(row.explanation_json)
        : null,
      evidence_json: undefined,
      explanation_json: undefined,
    };
  }
  list({ status = "open", type = "all", search = "" } = {}) {
    if (
      !["open", "dismissed", "all"].includes(status) ||
      ![
        "all",
        "new_destination",
        "new_service",
        "new_country",
        "traffic_spike",
      ].includes(type)
    )
      throw new Error("Choose valid alert filters.");
    const rows = this.q(
      "SELECT * FROM alerts WHERE (?='all' OR status=?) AND (?='all' OR type=?) AND instr(lower(app_name||' '||address),?)>0 ORDER BY observed_at DESC LIMIT 200",
    ).all(
      status,
      status,
      type,
      type,
      String(search).slice(0, 200).toLowerCase(),
    );
    const counts = this.q(
      "SELECT COUNT(*) total,SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) open,SUM(CASE WHEN type='traffic_spike' AND status='open' THEN 1 ELSE 0 END) spikes FROM alerts",
    ).get();
    const learned = this.q(
      "SELECT COUNT(*) count FROM (SELECT app_id FROM app_daily GROUP BY app_id HAVING SUM(observed_ms)>=?)",
    ).get(LEARN_MS).count;
    return {
      alerts: rows.map((row) => this.row(row)),
      counts: {
        total: counts.total,
        open: counts.open || 0,
        spikes: counts.spikes || 0,
      },
      learning: {
        eligibleApps: learned,
        minimumObservedMs: LEARN_MS,
        minimumMeasuredMinutes: 5,
      },
      updatedAt: this.store.clock(),
    };
  }
  openCount() {
    return this.q("SELECT COUNT(*) count FROM alerts WHERE status='open'").get()
      .count;
  }
  setStatus(id, status) {
    if (!["open", "dismissed"].includes(status))
      throw new Error("Invalid alert status.");
    const changed = this.q("UPDATE alerts SET status=? WHERE id=?").run(
      status,
      String(id),
    );
    if (!changed.changes) throw new Error("This alert is no longer available.");
    return true;
  }
  explainPayload(id, includeIPs = false) {
    const row = this.q("SELECT * FROM alerts WHERE id=?").get(String(id));
    if (!row) throw new Error("Select a saved alert.");
    const evidence = JSON.parse(row.evidence_json);
    if (!includeIPs) delete evidence.observed?.address;
    return {
      id: row.id,
      type: row.type,
      app: row.app_name,
      severity: row.severity,
      observedAt: row.observed_at,
      evidence,
    };
  }
  saveExplanation(id, reply) {
    this.q("UPDATE alerts SET explanation_json=? WHERE id=?").run(
      JSON.stringify({
        text: reply.text,
        provider: reply.provider,
        model: reply.model,
        generatedAt: reply.generatedAt,
      }),
      String(id),
    );
  }
}
module.exports = { Anomalies, median };
