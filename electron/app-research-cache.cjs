const { sourceURL, clean } = require("./assistant-tools.cjs");
const keyFor = (app) => {
  if (
    typeof app !== "string" ||
    !app.trim() ||
    app.length > 120 ||
    !/^[\p{L}\p{N} ._()+&'-]+$/u.test(app)
  )
    return null;
  return app
    .trim()
    .toLowerCase()
    .replace(/\s+/g, " ")
    .replace(/\.exe$/, "");
};
// An additive table in the existing traffic.sqlite. No credentials or row data.
class AppResearchCache {
  constructor(db, { clock = () => Date.now(), limit = 500 } = {}) {
    this.db = db;
    this.clock = clock;
    this.limit = limit;
    this.available = false;
    if (!db) return;
    let transaction = false;
    try {
      db.exec("BEGIN IMMEDIATE;");
      transaction = true;
      db.exec(
        "CREATE TABLE IF NOT EXISTS app_research_schema(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL); INSERT OR IGNORE INTO app_research_schema VALUES(1,1);",
      );
      if (
        db.prepare("SELECT version FROM app_research_schema WHERE id=1").get()
          .version !== 1
      )
        throw new Error("Unsupported research cache schema");
      db.exec(
        "CREATE TABLE IF NOT EXISTS app_research_cache(app_key TEXT PRIMARY KEY,result_json TEXT NOT NULL,researched_at INTEGER NOT NULL,saved_at INTEGER NOT NULL,last_used_at INTEGER NOT NULL);",
      );
      db.exec("COMMIT;");
      transaction = false;
      this.available = true;
    } catch {
      if (transaction)
        try {
          db.exec("ROLLBACK;");
        } catch {}
    }
  }
  normalize(app, result, config = {}) {
    const key = keyFor(app),
      secret = config.token;
    const safe = (value) =>
      clean(
        secret
          ? String(value ?? "")
              .split(secret)
              .join("[redacted]")
          : value,
        2000,
      );
    if (
      !key ||
      result?.status !== "completed" ||
      typeof result.text !== "string" ||
      !result.text.trim() ||
      result.text.length > 2000 ||
      !Number.isFinite(Date.parse(result.researchedAt))
    )
      return null;
    const name = safe(result.app || app);
    if (keyFor(name) !== key) return null;
    const provider = result.provider || config.provider,
      model = safe(result.model || config.model);
    if (
      !["openai", "openrouter"].includes(provider) ||
      !model ||
      model.length > 160
    )
      return null;
    if (
      !Array.isArray(result.sources) ||
      !result.sources.length ||
      result.sources.length > 8
    )
      return null;
    const sources = [];
    for (const source of result.sources) {
      const url = sourceURL(source?.url);
      let decoded = url;
      try {
        decoded = decodeURIComponent(url);
      } catch {}
      if (
        !url ||
        (secret && (url.includes(secret) || decoded.includes(secret)))
      )
        return null;
      if (!sources.some((s) => s.url === url))
        sources.push({
          url,
          title: safe(source.title || new URL(url).hostname).slice(0, 180),
        });
    }
    return {
      app: name,
      status: "completed",
      text: safe(result.text),
      sources,
      researchedAt: new Date(result.researchedAt).toISOString(),
      provider,
      model,
    };
  }
  get(app, config = {}) {
    const key = keyFor(app);
    if (!this.available || !key) return null;
    try {
      const row = this.db
        .prepare(
          "SELECT result_json,saved_at FROM app_research_cache WHERE app_key=?",
        )
        .get(key);
      if (!row || row.result_json.length > 32000) return null;
      const result = this.normalize(app, JSON.parse(row.result_json), {
        token: config.token,
      });
      if (!result) return null;
      try {
        this.db
          .prepare(
            "UPDATE app_research_cache SET last_used_at=? WHERE app_key=?",
          )
          .run(this.clock(), key);
      } catch {}
      return {
        ...result,
        cached: true,
        cacheSavedAt: new Date(row.saved_at).toISOString(),
      };
    } catch {
      return null;
    }
  }
  put(app, result, config) {
    if (!this.available) return false;
    const entry = this.normalize(app, result, config);
    if (!entry) return false;
    let transaction = false;
    try {
      this.db.exec("BEGIN IMMEDIATE;");
      transaction = true;
      const now = this.clock();
      this.db
        .prepare(
          "INSERT INTO app_research_cache VALUES(?,?,?,?,?) ON CONFLICT(app_key) DO UPDATE SET result_json=excluded.result_json,researched_at=excluded.researched_at,saved_at=excluded.saved_at,last_used_at=excluded.last_used_at",
        )
        .run(
          keyFor(app),
          JSON.stringify(entry),
          Date.parse(entry.researchedAt),
          now,
          now,
        );
      this.db
        .prepare(
          "DELETE FROM app_research_cache WHERE app_key NOT IN (SELECT app_key FROM app_research_cache ORDER BY last_used_at DESC,app_key LIMIT ?)",
        )
        .run(this.limit);
      this.db.exec("COMMIT;");
      transaction = false;
      return true;
    } catch {
      if (transaction)
        try {
          this.db.exec("ROLLBACK;");
        } catch {}
      return false;
    }
  }
}
module.exports = { AppResearchCache, keyFor };
