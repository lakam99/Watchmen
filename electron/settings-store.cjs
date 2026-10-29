const { DatabaseSync } = require("node:sqlite");
const fs = require("node:fs/promises"),
  path = require("node:path");
const { validateAI } = require("./ai-config.cjs");
const defaults = {
  preferences: {
    theme: "system",
    ai: {
      provider: "openrouter",
      baseUrl: "https://openrouter.ai/api/v1",
      model: "openai/gpt-4.1-mini",
    },
  },
  updates: { autoCheck: true, autoDownload: true },
  assistant: { shareIPs: false, ipLookups: false, webSearch: false },
  monitor: {
    page: "Overview",
    group: "app",
    filter: "all",
    lifecycle: "active",
    direction: "both",
    sort: "connections",
    adapter: "all",
    windowSize: 60,
    search: "",
    locationsEnabled: false,
  },
  window: { width: 1460, height: 960, maximized: false },
};
function normalize(key, value) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("Choose valid local settings.");
  if (key === "preferences") {
    if (!["system", "light", "dark"].includes(value.theme))
      throw new Error("Invalid appearance choice.");
    return { theme: value.theme, ai: validateAI(value.ai) };
  }
  if (key === "updates") {
    if (
      typeof value.autoCheck !== "boolean" ||
      typeof value.autoDownload !== "boolean"
    )
      throw new Error("Choose valid update preferences.");
    return { autoCheck: value.autoCheck, autoDownload: value.autoDownload };
  }
  if (key === "assistant") {
    const result = {};
    for (const field of ["shareIPs", "ipLookups", "webSearch"]) {
      if (typeof value[field] !== "boolean")
        throw new Error("Choose valid AI console permissions.");
      result[field] = value[field];
    }
    return result;
  }
  if (key === "window") {
    if (
      !Number.isInteger(value.width) ||
      value.width < 1000 ||
      value.width > 8192 ||
      !Number.isInteger(value.height) ||
      value.height < 720 ||
      value.height > 8192 ||
      typeof value.maximized !== "boolean"
    )
      throw new Error("Invalid window settings.");
    return {
      width: value.width,
      height: value.height,
      maximized: value.maximized,
    };
  }
  if (key === "monitor") {
    const fields = {
      page: [
        "Overview",
        "Applications",
        "Destinations",
        "Locations",
        "Connections",
        "Traffic profile",
        "Changes",
        "Packets",
        "Network rules",
        "AI console",
      ],
      group: ["app", "destination", "country", "protocol"],
      filter: ["all", "internet", "local", "listener"],
      lifecycle: ["active", "connected", "all"],
      direction: ["both", "in", "out"],
      sort: ["connections", "name", "download", "upload", "total"],
      windowSize: [60, 300],
    };
    const result = {};
    for (const [field, allowed] of Object.entries(fields)) {
      if (!allowed.includes(value[field]))
        throw new Error("Invalid monitor preference: " + field);
      result[field] = value[field];
    }
    if (
      typeof value.adapter !== "string" ||
      value.adapter.length > 200 ||
      typeof value.search !== "string" ||
      value.search.length > 200
    )
      throw new Error("Invalid monitor filter.");
    if (
      value.locationsEnabled !== undefined &&
      typeof value.locationsEnabled !== "boolean"
    )
      throw new Error("Invalid location lookup preference.");
    return {
      ...result,
      adapter: value.adapter,
      search: value.search,
      locationsEnabled: value.locationsEnabled === true,
    };
  }
  throw new Error("Unsupported settings group.");
}
class SettingsStore {
  constructor(directory) {
    this.path = path.join(directory, "traffic.sqlite");
    this.directory = directory;
    this.db = null;
    this.error = null;
    this.initializing = null;
    this.initialized = false;
  }
  async init() {
    if (this.initialized) return;
    if (this.initializing) return this.initializing;
    this.initializing = (async () => {
      try {
        await fs.mkdir(this.directory, { recursive: true });
        this.db = new DatabaseSync(this.path);
        this.db.exec("PRAGMA busy_timeout=2500;");
        const version = this.db
          .prepare("PRAGMA user_version")
          .get().user_version;
        if (version > 2)
          throw new Error(
            "This database was created by a newer Watchmen version.",
          );
        this.db.exec("PRAGMA journal_mode=WAL;");
        const legacy = {};
        for (const [key, filename] of [
          ["preferences", "settings.json"],
          ["updates", "update-settings.json"],
        ]) {
          try {
            const input = JSON.parse(
              await fs.readFile(path.join(this.directory, filename), "utf8"),
            );
            legacy[key] = normalize(key, {
              ...defaults[key],
              ...input,
              ...(key === "preferences"
                ? {
                    theme: ["system", "light", "dark"].includes(input.theme)
                      ? input.theme
                      : "system",
                  }
                : {}),
            });
          } catch (error) {
            if (error.code !== "ENOENT")
              this.error =
                "Some legacy settings could not be imported. Their original files were preserved.";
          }
        }
        this.db.exec("BEGIN IMMEDIATE;");
        try {
          this.db.exec(
            "CREATE TABLE IF NOT EXISTS settings_schema(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL); INSERT OR IGNORE INTO settings_schema VALUES(1,1);",
          );
          if (
            this.db
              .prepare("SELECT version FROM settings_schema WHERE id=1")
              .get().version !== 1
          )
            throw new Error(
              "The settings schema requires a newer Watchmen version.",
            );
          this.db.exec(
            "CREATE TABLE IF NOT EXISTS app_settings(key TEXT PRIMARY KEY,value_json TEXT NOT NULL,updated_at INTEGER NOT NULL);",
          );
          for (const key of Object.keys(defaults))
            this.db
              .prepare("INSERT OR IGNORE INTO app_settings VALUES(?,?,?)")
              .run(
                key,
                JSON.stringify(legacy[key] || defaults[key]),
                Date.now(),
              );
          this.db.exec("COMMIT;");
        } catch (error) {
          this.db.exec("ROLLBACK;");
          throw error;
        }
      } catch (error) {
        this.db?.close();
        this.db = null;
        this.error =
          "Local settings could not be opened. Existing data was preserved; saving settings is unavailable.";
      } finally {
        this.initialized = true;
        this.initializing = null;
      }
    })();
    return this.initializing;
  }
  get(key, fallback = defaults[key]) {
    if (!this.db) return structuredClone(fallback);
    try {
      const row = this.db
        .prepare("SELECT value_json FROM app_settings WHERE key=?")
        .get(key);
      return row
        ? normalize(key, JSON.parse(row.value_json))
        : structuredClone(fallback);
    } catch {
      this.error = "Saved local settings are invalid. Defaults are in use.";
      return structuredClone(fallback);
    }
  }
  async patch(key, input) {
    await this.init();
    if (!this.db) throw new Error(this.error);
    if (!Object.hasOwn(defaults, key))
      throw new Error("Unsupported settings group.");
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      const next = normalize(key, { ...this.get(key), ...input });
      this.db
        .prepare(
          "INSERT INTO app_settings VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at",
        )
        .run(key, JSON.stringify(next), Date.now());
      this.db.exec("COMMIT;");
      return next;
    } catch (error) {
      this.db.exec("ROLLBACK;");
      throw error;
    }
  }
  close() {
    this.db?.close();
    this.db = null;
  }
}
module.exports = { SettingsStore, defaults, normalize };
