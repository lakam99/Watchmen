const { DatabaseSync } = require("node:sqlite");
const fs = require("node:fs");
const path = require("node:path");
const { createHash, randomUUID } = require("node:crypto");
const { Anomalies } = require("./anomalies.cjs");
const DAY = 86400000;
const hash = (value) => createHash("sha256").update(value).digest("hex");
const str = (value, max = 1024) => String(value ?? "").slice(0, max);
const number = (value) =>
  Number.isFinite(value) && value >= 0
    ? Math.min(Math.floor(value), Number.MAX_SAFE_INTEGER)
    : 0;
function appIdentity(f) {
  const executable = str(f.processPath, 4096)
    .replaceAll("/", "\\")
    .toLowerCase();
  return hash(
    executable ? "path:" + executable : "name:" + str(f.app, 200).toLowerCase(),
  );
}
function addressScope(ip) {
  if (["*", "0.0.0.0", "::"].includes(ip)) return "listener";
  if (ip.startsWith("::ffff:")) return addressScope(ip.slice(7));
  if (ip.includes(":"))
    return ip === "::1" || /^(f[cd]|fe[89ab]|ff)/i.test(ip)
      ? "local"
      : "internet";
  const [a, b] = ip.split(".").map(Number);
  return a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127)
    ? "local"
    : "internet";
}
class TrafficStore {
  constructor(
    filename,
    { clock = () => Date.now(), sessionId = randomUUID() } = {},
  ) {
    this.path = filename;
    this.clock = clock;
    this.sessionId = sessionId;
    this.owner = false;
    this.closed = false;
    this.lastWrite = 0;
    this.statements = new Map();
    fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(filename);
    try {
      this.db.exec(
        "PRAGMA busy_timeout=1000; PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;",
      );
      const version = this.db.prepare("PRAGMA user_version").get().user_version;
      if (version > 2)
        throw new Error(
          "This traffic database was created by a newer Watchmen version.",
        );
      this.db.exec(`BEGIN IMMEDIATE;
    CREATE TABLE IF NOT EXISTS capture_lease(id INTEGER PRIMARY KEY CHECK(id=1),owner TEXT,expires_at INTEGER NOT NULL,priority INTEGER NOT NULL);
    INSERT OR IGNORE INTO capture_lease VALUES(1,NULL,0,0);
    CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,started_at INTEGER NOT NULL,last_seen INTEGER NOT NULL,ended_at INTEGER,last_timestamp INTEGER NOT NULL,tracing INTEGER NOT NULL,samples INTEGER NOT NULL DEFAULT 0,events_lost INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS applications(id TEXT PRIMARY KEY,name TEXT NOT NULL,path TEXT NOT NULL,first_seen INTEGER NOT NULL,last_seen INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS destinations(address TEXT PRIMARY KEY,scope TEXT NOT NULL,first_seen INTEGER NOT NULL,last_seen INTEGER NOT NULL,country TEXT NOT NULL DEFAULT '',city TEXT NOT NULL DEFAULT '',org TEXT NOT NULL DEFAULT '',lookup_at INTEGER NOT NULL DEFAULT 0,latitude REAL,longitude REAL);
    CREATE TABLE IF NOT EXISTS edges(app_id TEXT NOT NULL REFERENCES applications(id),address TEXT NOT NULL REFERENCES destinations(address),protocol TEXT NOT NULL,port INTEGER NOT NULL,local_service_port INTEGER NOT NULL,first_seen INTEGER NOT NULL,last_seen INTEGER NOT NULL,received INTEGER NOT NULL DEFAULT 0,sent INTEGER NOT NULL DEFAULT 0,observations INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(app_id,address,protocol,port,local_service_port));
    CREATE TABLE IF NOT EXISTS flow_cursors(session_id TEXT NOT NULL REFERENCES sessions(id),flow_key TEXT NOT NULL,app_id TEXT NOT NULL REFERENCES applications(id),address TEXT NOT NULL,protocol TEXT NOT NULL,port INTEGER NOT NULL,local_address TEXT NOT NULL,local_port INTEGER NOT NULL,pid INTEGER NOT NULL,first_seen INTEGER NOT NULL,last_seen INTEGER NOT NULL,state TEXT NOT NULL,received INTEGER NOT NULL,sent INTEGER NOT NULL,PRIMARY KEY(session_id,flow_key));
    CREATE INDEX IF NOT EXISTS cursors_last_seen ON flow_cursors(last_seen);
    CREATE TABLE IF NOT EXISTS app_sessions(app_id TEXT NOT NULL REFERENCES applications(id),session_id TEXT NOT NULL REFERENCES sessions(id),last_seen INTEGER NOT NULL,PRIMARY KEY(app_id,session_id));
    CREATE TABLE IF NOT EXISTS app_daily(day TEXT NOT NULL,app_id TEXT NOT NULL REFERENCES applications(id),received INTEGER NOT NULL DEFAULT 0,sent INTEGER NOT NULL DEFAULT 0,observations INTEGER NOT NULL DEFAULT 0,observed_ms INTEGER NOT NULL DEFAULT 0,measured_ms INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(day,app_id));
    CREATE TABLE IF NOT EXISTS edge_daily(day TEXT NOT NULL,app_id TEXT NOT NULL REFERENCES applications(id),address TEXT NOT NULL REFERENCES destinations(address),protocol TEXT NOT NULL,port INTEGER NOT NULL,local_service_port INTEGER NOT NULL,received INTEGER NOT NULL DEFAULT 0,sent INTEGER NOT NULL DEFAULT 0,observations INTEGER NOT NULL DEFAULT 0,measured_ms INTEGER NOT NULL DEFAULT 0,last_seen INTEGER NOT NULL,PRIMARY KEY(day,app_id,address,protocol,port,local_service_port));
    CREATE INDEX IF NOT EXISTS edges_app ON edge_daily(app_id,day);
    CREATE INDEX IF NOT EXISTS edges_destination ON edge_daily(address,day);
    CREATE INDEX IF NOT EXISTS apps_daily_app ON app_daily(app_id,day);
    `);
      this.anomalies = new Anomalies(this);
      this.anomalies.initialize();
      this.db.exec("PRAGMA user_version=2; COMMIT;");
    } catch (error) {
      try {
        this.db.exec("ROLLBACK");
      } catch {}
      this.db.close();
      throw error;
    }
  }
  q(sql) {
    let statement = this.statements.get(sql);
    if (!statement) {
      statement = this.db.prepare(sql);
      this.statements.set(sql, statement);
    }
    return statement;
  }
  ingest(snapshot, { force = false } = {}) {
    const timestamp = Date.parse(snapshot?.timestamp);
    if (!Number.isFinite(timestamp) || !Array.isArray(snapshot.flows))
      return false;
    if (!force && timestamp - this.lastWrite < 2000) return false;
    const now = this.clock(),
      priority = snapshot.tracing ? 3 : 1;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const lease = this.q("SELECT * FROM capture_lease WHERE id=1").get();
      if (
        lease.owner !== this.sessionId &&
        lease.expires_at > now &&
        lease.priority >= priority
      ) {
        this.owner = false;
        this.db.exec("COMMIT");
        return false;
      }
      const acquired =
        !this.owner ||
        lease.owner !== this.sessionId ||
        lease.expires_at <= now;
      this.q(
        "UPDATE capture_lease SET owner=?,expires_at=?,priority=? WHERE id=1",
      ).run(this.sessionId, now + 8000, priority);
      const previous = this.q("SELECT * FROM sessions WHERE id=?").get(
        this.sessionId,
      );
      if (previous && timestamp <= previous.last_timestamp) {
        this.owner = true;
        this.db.exec("COMMIT");
        return false;
      }
      const elapsed =
        !acquired && previous && timestamp - previous.last_timestamp <= 5000
          ? Math.max(0, timestamp - previous.last_timestamp)
          : 0;
      const measured =
        !!snapshot.tracing && previous?.tracing === 1 && !acquired;
      this.q(
        `INSERT INTO sessions(id,started_at,last_seen,last_timestamp,tracing,samples,events_lost) VALUES(?,?,?,?,?,1,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,last_timestamp=excluded.last_timestamp,tracing=excluded.tracing,samples=samples+1,events_lost=MAX(events_lost,excluded.events_lost),ended_at=NULL`,
      ).run(
        this.sessionId,
        Date.parse(snapshot.startedAt) || timestamp,
        timestamp,
        timestamp,
        snapshot.tracing ? 1 : 0,
        number(snapshot.eventsLost),
      );
      const apps = new Map(),
        destinations = new Map(),
        edges = new Map();
      const day = new Date(timestamp).toISOString().slice(0, 10);
      for (const f of snapshot.flows) {
        const appId = appIdentity(f),
          address = str(f.remoteAddress, 128).toLowerCase(),
          scope = addressScope(address),
          protocol = f.protocol === "UDP" ? "UDP" : "TCP",
          port = number(f.remotePort),
          localServicePort = scope === "listener" ? number(f.localPort) : 0;
        const key = hash(str(f.id, 2048) + "|" + str(f.firstSeen, 64));
        const old = this.q(
          "SELECT received,sent,state FROM flow_cursors WHERE session_id=? AND flow_key=?",
        ).get(this.sessionId, key);
        const rx = number(f.received),
          tx = number(f.sent);
        if (!f.active && !old && rx + tx === 0) continue;
        if (!f.active && old && old.received === rx && old.sent === tx) {
          if (old.state !== f.state)
            this.q(
              "UPDATE flow_cursors SET state=?,last_seen=MAX(last_seen,?) WHERE session_id=? AND flow_key=?",
            ).run(str(f.state, 40), timestamp, this.sessionId, key);
          continue;
        }
        if (
          !f.active &&
          !old &&
          Date.parse(f.lastSeen || f.firstSeen) <
            (previous?.last_timestamp || timestamp)
        )
          continue;
        const recent =
          Date.parse(f.firstSeen) >=
          (previous?.last_timestamp || timestamp) - 1000;
        const received =
            measured && (old || recent)
              ? Math.max(0, rx - (old?.received || 0))
              : 0,
          sent =
            measured && (old || recent)
              ? Math.max(0, tx - (old?.sent || 0))
              : 0;
        let a = apps.get(appId);
        if (!a) {
          a = {
            id: appId,
            name: str(f.app, 200) || "Unknown application",
            path: str(f.processPath, 4096),
            received: 0,
            sent: 0,
            observations: 0,
          };
          apps.set(appId, a);
          this.q(
            "INSERT INTO applications VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=MAX(last_seen,excluded.last_seen),name=excluded.name",
          ).run(appId, a.name, a.path, timestamp, timestamp);
        }
        a.received += received;
        a.sent += sent;
        if (old && (rx < old.received || tx < old.sent)) a.counterReset = true;
        if (!old) a.observations++;
        destinations.set(address, scope);
        const edgeKey = JSON.stringify([
          appId,
          address,
          protocol,
          port,
          localServicePort,
        ]);
        let e = edges.get(edgeKey);
        if (!e) {
          e = {
            appId,
            address,
            protocol,
            port,
            localServicePort,
            received: 0,
            sent: 0,
            observations: 0,
          };
          edges.set(edgeKey, e);
        }
        e.received += received;
        e.sent += sent;
        if (!old) e.observations++;
        this.q(
          `INSERT INTO flow_cursors VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(session_id,flow_key) DO UPDATE SET last_seen=excluded.last_seen,state=excluded.state,received=excluded.received,sent=excluded.sent`,
        ).run(
          this.sessionId,
          key,
          appId,
          address,
          protocol,
          port,
          str(f.localAddress, 128),
          number(f.localPort),
          number(f.pid),
          Date.parse(f.firstSeen) || timestamp,
          timestamp,
          str(f.state, 40),
          rx,
          tx,
        );
      }
      for (const [address, scope] of destinations)
        this.q(
          "INSERT INTO destinations(address,scope,first_seen,last_seen) VALUES(?,?,?,?) ON CONFLICT(address) DO UPDATE SET last_seen=MAX(last_seen,excluded.last_seen)",
        ).run(address, scope, timestamp, timestamp);
      this.anomalies.observe({
        apps,
        edges,
        timestamp,
        measured,
        elapsed,
        quality:
          !previous || number(snapshot.eventsLost) <= previous.events_lost,
      });
      for (const a of apps.values()) {
        this.q(
          "INSERT INTO app_sessions VALUES(?,?,?) ON CONFLICT(app_id,session_id) DO UPDATE SET last_seen=excluded.last_seen",
        ).run(a.id, this.sessionId, timestamp);
        this.q(
          `INSERT INTO app_daily VALUES(?,?,?,?,?,?,?) ON CONFLICT(day,app_id) DO UPDATE SET received=received+excluded.received,sent=sent+excluded.sent,observations=observations+excluded.observations,observed_ms=observed_ms+excluded.observed_ms,measured_ms=measured_ms+excluded.measured_ms`,
        ).run(
          day,
          a.id,
          a.received,
          a.sent,
          a.observations,
          elapsed,
          measured ? elapsed : 0,
        );
      }
      for (const e of edges.values()) {
        this.q(
          `INSERT INTO edges VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(app_id,address,protocol,port,local_service_port) DO UPDATE SET last_seen=MAX(last_seen,excluded.last_seen),received=received+excluded.received,sent=sent+excluded.sent,observations=observations+excluded.observations`,
        ).run(
          e.appId,
          e.address,
          e.protocol,
          e.port,
          e.localServicePort,
          timestamp,
          timestamp,
          e.received,
          e.sent,
          e.observations,
        );
        this.q(
          `INSERT INTO edge_daily VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(day,app_id,address,protocol,port,local_service_port) DO UPDATE SET received=received+excluded.received,sent=sent+excluded.sent,observations=observations+excluded.observations,measured_ms=measured_ms+excluded.measured_ms,last_seen=MAX(last_seen,excluded.last_seen)`,
        ).run(
          day,
          e.appId,
          e.address,
          e.protocol,
          e.port,
          e.localServicePort,
          e.received,
          e.sent,
          e.observations,
          measured ? elapsed : 0,
          timestamp,
        );
      }
      for (const address of destinations.keys())
        this.anomalies.location(address, timestamp);
      if (!this.prunedAt || now - this.prunedAt > DAY) {
        this.q("DELETE FROM flow_cursors WHERE last_seen<?").run(
          now - 30 * DAY,
        );
        this.prunedAt = now;
      }
      this.db.exec("COMMIT");
      this.owner = true;
      this.lastWrite = timestamp;
      return true;
    } catch (error) {
      try {
        this.db.exec("ROLLBACK");
      } catch {}
      this.owner = false;
      throw error;
    }
  }
  range(value = "all") {
    if (!["all", "7d", "30d", "90d"].includes(value))
      throw new Error("Choose a valid profile time range.");
    const day =
      value === "all"
        ? "0000-01-01"
        : new Date(this.clock() - (Number(value.slice(0, -1)) - 1) * DAY)
            .toISOString()
            .slice(0, 10);
    return {
      day,
      since: day === "0000-01-01" ? 0 : Date.parse(day + "T00:00:00Z"),
    };
  }
  summary({ range = "all", search = "" } = {}) {
    const { day, since } = this.range(range);
    const query = str(search, 200).toLowerCase();
    const totals = this.q(
      `SELECT COUNT(DISTINCT app_id) applications,COALESCE(SUM(received),0) received,COALESCE(SUM(sent),0) sent,COALESCE(SUM(observations),0) observations,COALESCE(SUM(measured_ms),0) measuredMs FROM app_daily WHERE day>=?`,
    ).get(day);
    totals.destinations = this.q(
      "SELECT COUNT(DISTINCT e.address) count FROM edge_daily e JOIN destinations d ON d.address=e.address WHERE e.day>=? AND d.scope!='listener'",
    ).get(day).count;
    totals.sessions = this.q(
      "SELECT COUNT(*) count FROM sessions WHERE last_seen>=?",
    ).get(since).count;
    const applications = this.q(
      `SELECT a.id,a.name,a.path,a.first_seen firstSeen,a.last_seen lastSeen,SUM(d.received) received,SUM(d.sent) sent,SUM(d.observations) observations,SUM(d.measured_ms) measuredMs,SUM(d.observed_ms) observedMs,(SELECT COUNT(*) FROM app_sessions s WHERE s.app_id=a.id AND s.last_seen>=?) sessions,(SELECT COUNT(DISTINCT e.address) FROM edge_daily e JOIN destinations x ON x.address=e.address WHERE e.app_id=a.id AND e.day>=? AND x.scope!='listener') destinations FROM app_daily d JOIN applications a ON a.id=d.app_id WHERE d.day>=? AND instr(lower(a.name||' '||a.path),?)>0 GROUP BY a.id ORDER BY received+sent DESC,observations DESC,a.name LIMIT 200`,
    ).all(since, day, day, query);
    const destinations = this.q(
      `SELECT d.address,d.scope,d.country,d.city,d.org,d.first_seen firstSeen,d.last_seen lastSeen,SUM(e.received) received,SUM(e.sent) sent,SUM(e.observations) observations,SUM(e.measured_ms) measuredMs,COUNT(DISTINCT e.app_id) applications,COUNT(DISTINCT e.protocol||':'||e.port||':'||e.local_service_port) services FROM edge_daily e JOIN destinations d ON d.address=e.address WHERE e.day>=? AND instr(lower(d.address||' '||d.country||' '||d.org),?)>0 GROUP BY d.address ORDER BY received+sent DESC,observations DESC LIMIT 200`,
    ).all(day, query);
    const daily = this.q(
      "SELECT day,SUM(received) received,SUM(sent) sent,SUM(observations) observations,SUM(measured_ms) measuredMs FROM app_daily WHERE day>=? GROUP BY day ORDER BY day DESC LIMIT 30",
    )
      .all(day)
      .reverse();
    const protocols = this.q(
      "SELECT protocol,SUM(observations) observations,COUNT(DISTINCT app_id) applications FROM edge_daily WHERE day>=? GROUP BY protocol",
    ).all(day);
    const countries = this.q(
      "SELECT d.country,COUNT(DISTINCT e.address) destinations FROM edge_daily e JOIN destinations d ON d.address=e.address WHERE e.day>=? AND d.country!='' GROUP BY d.country ORDER BY destinations DESC LIMIT 8",
    ).all(day);
    return {
      databasePath: this.path,
      schemaVersion: 2,
      range,
      updatedAt: this.clock(),
      totals,
      applications,
      destinations,
      daily,
      protocols,
      countries,
      firstSeen: this.q("SELECT MIN(first_seen) value FROM applications").get()
        .value,
      eventsLost: this.q(
        "SELECT COALESCE(SUM(events_lost),0) count FROM sessions WHERE last_seen>=?",
      ).get(since).count,
      recording: this.isRecorder(),
    };
  }
  detail({ appId, range = "all" } = {}) {
    if (typeof appId !== "string" || !/^[a-f0-9]{64}$/.test(appId))
      throw new Error("Choose an application profile.");
    const { day } = this.range(range);
    return {
      application:
        this.q(
          "SELECT id,name,path,first_seen firstSeen,last_seen lastSeen FROM applications WHERE id=?",
        ).get(appId) || null,
      endpoints: this.q(
        `SELECT e.address,d.scope,d.country,d.org,e.protocol,e.port,e.local_service_port localServicePort,SUM(e.received) received,SUM(e.sent) sent,SUM(e.observations) observations,SUM(e.measured_ms) measuredMs,MIN(p.first_seen) firstSeen,MAX(e.last_seen) lastSeen FROM edge_daily e JOIN destinations d ON d.address=e.address JOIN edges p ON p.app_id=e.app_id AND p.address=e.address AND p.protocol=e.protocol AND p.port=e.port AND p.local_service_port=e.local_service_port WHERE e.app_id=? AND e.day>=? GROUP BY e.address,e.protocol,e.port,e.local_service_port ORDER BY SUM(e.observations) DESC,SUM(e.received)+SUM(e.sent) DESC LIMIT 200`,
      ).all(appId, day),
    };
  }
  saveLocation(address, g) {
    if (!g || !g.country || g.country === "Lookup unavailable") return;
    this.q(
      "UPDATE destinations SET country=?,city=?,org=?,lookup_at=?,latitude=?,longitude=? WHERE address=?",
    ).run(
      str(g.country, 120),
      str(g.city, 120),
      str(g.org, 200),
      this.clock(),
      Number.isFinite(g.latitude) ? g.latitude : null,
      Number.isFinite(g.longitude) ? g.longitude : null,
      address,
    );
    this.anomalies.location(address, this.clock());
  }
  cachedLocations() {
    return Object.fromEntries(
      this.q(
        "SELECT address,country,city,org,latitude,longitude FROM destinations WHERE lookup_at>? AND country!='' ORDER BY lookup_at DESC LIMIT 5000",
      )
        .all(this.clock() - 7 * DAY)
        .map(({ address, ...g }) => [address, g]),
    );
  }
  baseline(flows) {
    return [...new Set(flows.map(appIdentity))]
      .slice(0, 20)
      .map((id) => {
        const app = this.q(
          `SELECT a.name app,a.first_seen firstSeen,a.last_seen lastSeen,SUM(d.received) received,SUM(d.sent) sent,SUM(d.measured_ms) measuredMs,COUNT(DISTINCT d.day) daysObserved,(SELECT COUNT(*) FROM app_sessions s WHERE s.app_id=a.id) sessions,(SELECT COUNT(DISTINCT address) FROM edges e JOIN destinations x USING(address) WHERE e.app_id=a.id AND x.scope!='listener') destinations FROM applications a JOIN app_daily d ON d.app_id=a.id WHERE a.id=? GROUP BY a.id`,
        ).get(id);
        if (!app) return null;
        app.usualPorts = this.q(
          "SELECT protocol,port,SUM(observations) observations FROM edges WHERE app_id=? AND port>0 GROUP BY protocol,port ORDER BY observations DESC LIMIT 8",
        ).all(id);
        if (!app.measuredMs) {
          app.received = null;
          app.sent = null;
        }
        delete app.measuredMs;
        return app;
      })
      .filter(Boolean);
  }
  isRecorder() {
    const lease = this.q(
      "SELECT owner,expires_at FROM capture_lease WHERE id=1",
    ).get();
    return lease.owner === this.sessionId && lease.expires_at > this.clock();
  }
  close() {
    if (this.closed) return;
    try {
      this.q(
        "UPDATE capture_lease SET owner=NULL,expires_at=0,priority=0 WHERE id=1 AND owner=?",
      ).run(this.sessionId);
      this.q("UPDATE sessions SET ended_at=? WHERE id=?").run(
        this.clock(),
        this.sessionId,
      );
    } finally {
      this.db.close();
      this.closed = true;
    }
  }
}
module.exports = { TrafficStore, appIdentity, addressScope };
