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
    const columns = new Set(
      this.store.db
        .prepare("PRAGMA table_info(alerts)")
        .all()
        .map((row) => row.name),
    );
    if (!columns.has("last_seen"))
      this.store.db.exec(
        "ALTER TABLE alerts ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0;",
      );
    if (!columns.has("occurrences"))
      this.store.db.exec(
        "ALTER TABLE alerts ADD COLUMN occurrences INTEGER NOT NULL DEFAULT 1;",
      );
    this.store.db.exec(
      "CREATE TABLE IF NOT EXISTS alert_events(dedupe_key TEXT PRIMARY KEY,alert_id TEXT NOT NULL,observed_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS detector_migrations(name TEXT PRIMARY KEY); CREATE INDEX IF NOT EXISTS alerts_app_group ON alerts(app_id,type,status,last_seen);",
    );
    if (
      !this.q(
        "SELECT 1 FROM detector_migrations WHERE name='grouped_changes_v1'",
      ).get()
    ) {
      this.store.db.exec(
        "UPDATE alerts SET last_seen=observed_at WHERE last_seen=0; INSERT OR IGNORE INTO alert_events SELECT dedupe_key,id,observed_at FROM alerts;",
      );
      this.store.db.exec(
        "UPDATE alerts SET status='archived' WHERE status='open' AND type='new_service' AND json_extract(evidence_json,'$.observed.port')>=49152;",
      );
      const groups = this.q(
        "SELECT app_id,type,COALESCE(json_extract(evidence_json,'$.baseline.direction'),'') dimension FROM alerts WHERE status='open' GROUP BY app_id,type,dimension HAVING COUNT(*)>1",
      ).all();
      for (const group of groups) {
        const rows = this.q(
          "SELECT * FROM alerts WHERE app_id=? AND type=? AND status='open' AND COALESCE(json_extract(evidence_json,'$.baseline.direction'),'')=? ORDER BY observed_at,id",
        ).all(group.app_id, group.type, group.dimension);
        const first = rows[0],
          evidence = JSON.parse(first.evidence_json);
        const count = rows.reduce((sum, row) => sum + row.occurrences, 0),
          last = rows.reduce((value, row) => Math.max(value, row.last_seen), 0);
        evidence.activity = {
          occurrences: count,
          lastObservedAt: last,
          recent: rows.slice(-20).map((row) => ({
            ...JSON.parse(row.evidence_json).observed,
            observedAt: row.last_seen,
          })),
        };
        this.q(
          "UPDATE alerts SET occurrences=?,last_seen=?,evidence_json=? WHERE id=?",
        ).run(count, last, JSON.stringify(evidence), first.id);
        for (const row of rows.slice(1))
          this.q("UPDATE alerts SET status='archived' WHERE id=?").run(row.id);
      }
      this.q(
        "INSERT INTO detector_migrations VALUES('grouped_changes_v1')",
      ).run();
    }
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
    this.store.db.exec("SAVEPOINT add_change;");
    try {
      const inserted = this.q(
        "INSERT OR IGNORE INTO alert_events VALUES(?,'',?)",
      ).run(key, timestamp);
      if (!inserted.changes) {
        this.store.db.exec("RELEASE add_change;");
        return;
      }
      const old = this.q("SELECT id FROM alerts WHERE dedupe_key=?").get(key);
      if (old) {
        this.q("UPDATE alert_events SET alert_id=? WHERE dedupe_key=?").run(
          old.id,
          key,
        );
        this.store.db.exec("RELEASE add_change;");
        return;
      }
      const dimension = evidence.baseline.direction || "";
      const existing = this.q(
        "SELECT * FROM alerts WHERE app_id=? AND type=? AND status='open' AND COALESCE(NULLIF(last_seen,0),observed_at)>=? AND COALESCE(json_extract(evidence_json,'$.baseline.direction'),'')=? ORDER BY observed_at,id LIMIT 1",
      ).get(appId, type, timestamp - DAY, dimension);
      let id;
      if (existing) {
        id = existing.id;
        const saved = JSON.parse(existing.evidence_json),
          count = existing.occurrences + 1;
        const recent = [
          ...(saved.activity?.recent || [
            { ...saved.observed, observedAt: existing.observed_at },
          ]),
          { ...evidence.observed, observedAt: timestamp },
        ].slice(-20);
        saved.activity = {
          occurrences: count,
          lastObservedAt: timestamp,
          recent,
        };
        this.q(
          "UPDATE alerts SET occurrences=?,last_seen=MAX(last_seen,?),evidence_json=? WHERE id=?",
        ).run(count, timestamp, JSON.stringify(saved), id);
      } else {
        id = randomUUID();
        const initial = {
          version: 1,
          ...evidence,
          activity: {
            occurrences: 1,
            lastObservedAt: timestamp,
            recent: [{ ...evidence.observed, observedAt: timestamp }],
          },
        };
        this.q(
          "INSERT INTO alerts(id,dedupe_key,type,app_id,app_name,address,severity,observed_at,evidence_json,last_seen,occurrences) VALUES(?,?,?,?,?,?,?,?,?,?,1)",
        ).run(
          id,
          key,
          type,
          appId,
          appName,
          address,
          severity,
          timestamp,
          JSON.stringify(initial),
          timestamp,
        );
      }
      this.q("UPDATE alert_events SET alert_id=? WHERE dedupe_key=?").run(
        id,
        key,
      );
      this.store.db.exec("RELEASE add_change;");
    } catch (error) {
      this.store.db.exec("ROLLBACK TO add_change; RELEASE add_change;");
      throw error;
    }
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
        edge.port <= 49151 &&
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
      !["open", "dismissed", "archived", "all"].includes(status) ||
      ![
        "all",
        "new_destination",
        "new_service",
        "new_country",
        "traffic_spike",
      ].includes(type)
    )
      throw new Error("Choose valid alert filters.");
    const cutoff = this.store.clock() - DAY;
    const rows = this.q(
      `WITH source AS (
      SELECT *,COALESCE(NULLIF(last_seen,0),observed_at) effective_seen,
      CASE WHEN status='open' AND (COALESCE(NULLIF(last_seen,0),observed_at)<? OR (type='new_service' AND json_extract(evidence_json,'$.observed.port')>=49152)) THEN 'archived' ELSE status END effective_status,
      CASE WHEN status='open' AND COALESCE(NULLIF(last_seen,0),observed_at)>=? AND (type!='new_service' OR json_extract(evidence_json,'$.observed.port')<49152) THEN app_id||':'||type||':'||COALESCE(json_extract(evidence_json,'$.baseline.direction'),'') ELSE id END visible_group FROM alerts
    ), grouped AS (SELECT *,ROW_NUMBER() OVER(PARTITION BY visible_group ORDER BY observed_at,id) rank,SUM(occurrences) OVER(PARTITION BY visible_group) grouped_count,MAX(effective_seen) OVER(PARTITION BY visible_group) grouped_seen FROM source)
    SELECT * FROM grouped WHERE rank=1 AND (?='all' OR effective_status=?) AND (?='all' OR type=?) AND instr(lower(app_name||' '||address),?)>0 ORDER BY grouped_seen DESC LIMIT 200`,
    ).all(
      cutoff,
      cutoff,
      status,
      status,
      type,
      type,
      String(search).slice(0, 200).toLowerCase(),
    );
    const counts = this.q(
      `SELECT COUNT(*) open,SUM(CASE WHEN type='traffic_spike' THEN 1 ELSE 0 END) spikes FROM (SELECT app_id,type,COALESCE(json_extract(evidence_json,'$.baseline.direction'),'') dimension FROM alerts WHERE status='open' AND COALESCE(NULLIF(last_seen,0),observed_at)>=? AND (type!='new_service' OR json_extract(evidence_json,'$.observed.port')<49152) GROUP BY app_id,type,dimension)`,
    ).get(cutoff);
    const total = this.q("SELECT COUNT(*) total FROM alerts").get().total;
    const learned = this.q(
      "SELECT COUNT(*) count FROM (SELECT app_id FROM app_daily GROUP BY app_id HAVING SUM(observed_ms)>=?)",
    ).get(LEARN_MS).count;
    return {
      alerts: rows.map((row) =>
        this.row({
          ...row,
          status: row.effective_status,
          occurrences: row.grouped_count,
          last_seen: row.grouped_seen,
          visible_group: undefined,
          effective_seen: undefined,
          effective_status: undefined,
          rank: undefined,
          grouped_count: undefined,
          grouped_seen: undefined,
        }),
      ),
      counts: {
        total,
        open: counts.open || 0,
        spikes: counts.spikes || 0,
      },
      learning: {
        eligibleApps: learned,
        minimumObservedMs: LEARN_MS,
        minimumMeasuredMinutes: 5,
      },
      reviewWindowHours: 24,
      updatedAt: this.store.clock(),
    };
  }
  openCount() {
    return this.q(
      "SELECT COUNT(*) count FROM (SELECT app_id,type,COALESCE(json_extract(evidence_json,'$.baseline.direction'),'') dimension FROM alerts WHERE status='open' AND COALESCE(NULLIF(last_seen,0),observed_at)>=? AND (type!='new_service' OR json_extract(evidence_json,'$.observed.port')<49152) GROUP BY app_id,type,dimension)",
    ).get(this.store.clock() - DAY).count;
  }
  setStatus(id, status) {
    if (!["open", "dismissed"].includes(status))
      throw new Error("Invalid alert status.");
    const row = this.q("SELECT * FROM alerts WHERE id=?").get(String(id));
    if (!row) throw new Error("This alert is no longer available.");
    const dimension = JSON.parse(row.evidence_json).baseline.direction || "";
    if (status === "dismissed")
      this.q(
        "UPDATE alerts SET status='dismissed' WHERE (app_id=? AND type=? AND status='open' AND COALESCE(json_extract(evidence_json,'$.baseline.direction'),'')=?) OR id=?",
      ).run(row.app_id, row.type, dimension, row.id);
    else {
      const current = this.q(
        "SELECT id FROM alerts WHERE app_id=? AND type=? AND status='open' AND COALESCE(NULLIF(last_seen,0),observed_at)>=? AND COALESCE(json_extract(evidence_json,'$.baseline.direction'),'')=? AND id!=? LIMIT 1",
      ).get(row.app_id, row.type, this.store.clock() - DAY, dimension, row.id);
      if (current)
        throw new Error(
          "This app already has an open change of this type. Review that group first.",
        );
      this.q("UPDATE alerts SET status='open',last_seen=? WHERE id=?").run(
        this.store.clock(),
        row.id,
      );
    }
    return true;
  }
  dismissAll() {
    return this.q(
      "UPDATE alerts SET status='dismissed' WHERE status='open'",
    ).run().changes;
  }
  explainPayload(id, includeIPs = false) {
    const row = this.q("SELECT * FROM alerts WHERE id=?").get(String(id));
    if (!row) throw new Error("Select a saved alert.");
    const evidence = JSON.parse(row.evidence_json);
    if (!includeIPs) {
      delete evidence.observed?.address;
      for (const item of evidence.activity?.recent || []) delete item.address;
    }
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
