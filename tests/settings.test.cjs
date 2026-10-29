const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs/promises"),
  os = require("node:os"),
  path = require("node:path"),
  { DatabaseSync } = require("node:sqlite"),
  { SettingsStore } = require("../electron/settings-store.cjs"),
  { Preferences } = require("../electron/preferences.cjs");
async function fixture(t) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "watchmen-settings-")),
    stores = [];
  t.after(async () => {
    for (const store of stores) store.close();
    assert.equal(path.dirname(dir), os.tmpdir());
    assert.ok(path.basename(dir).startsWith("watchmen-settings-"));
    await fs.rm(dir, { recursive: true, force: true });
  });
  return {
    dir,
    open: () => {
      const store = new SettingsStore(dir);
      stores.push(store);
      return store;
    },
  };
}
test("legacy preferences migrate once into the traffic database and unknown credential fields are stripped", async (t) => {
  const f = await fixture(t),
    legacy = {
      theme: "dark",
      ai: {
        provider: "openrouter",
        baseUrl: "https://openrouter.ai/api/v1",
        model: "fixture/model",
        token: "must-not-migrate",
      },
      token: "must-not-migrate",
    };
  await fs.writeFile(path.join(f.dir, "settings.json"), JSON.stringify(legacy));
  await fs.writeFile(
    path.join(f.dir, "update-settings.json"),
    JSON.stringify({
      autoCheck: false,
      autoDownload: false,
      token: "must-not-migrate",
    }),
  );
  const first = f.open();
  await first.init();
  assert.equal(first.get("preferences").theme, "dark");
  assert.equal(first.get("updates").autoDownload, false);
  assert.equal(
    first.db
      .prepare(
        "SELECT COUNT(*) count FROM app_settings WHERE value_json LIKE '%must-not-migrate%'",
      )
      .get().count,
    0,
  );
  await first.patch("preferences", { theme: "light" });
  first.close();
  const next = f.open();
  await next.init();
  assert.equal(next.get("preferences").theme, "light");
  assert.equal(
    JSON.parse(await fs.readFile(path.join(f.dir, "settings.json"))).theme,
    "dark",
  );
});
test("two instances patch separate preferences without losing each other's saved settings", async (t) => {
  const f = await fixture(t),
    a = f.open(),
    b = f.open();
  await Promise.all([a.init(), b.init()]);
  await a.patch("preferences", { theme: "dark" });
  await b.patch("preferences", {
    ai: {
      provider: "openrouter",
      baseUrl: "https://openrouter.ai/api/v1",
      model: "new/model",
    },
  });
  assert.equal(a.get("preferences").theme, "dark");
  assert.equal(a.get("preferences").ai.model, "new/model");
  await a.patch("monitor", {
    locationsEnabled: true,
    group: "country",
    filter: "internet",
    windowSize: 300,
  });
  assert.equal(b.get("monitor").group, "country");
  assert.equal(b.get("monitor").windowSize, 300);
  assert.equal(b.get("monitor").locationsEnabled, true);
});
test("corrupt and future databases are preserved and settings writes fail closed", async (t) => {
  const f = await fixture(t),
    filename = path.join(f.dir, "traffic.sqlite"),
    bytes = Buffer.from("not sqlite - keep me");
  await fs.writeFile(filename, bytes);
  const broken = f.open();
  await broken.init();
  await assert.rejects(
    broken.patch("preferences", { theme: "dark" }),
    /unavailable/,
  );
  assert.deepEqual(await fs.readFile(filename), bytes);
  await fs.rm(filename);
  const db = new DatabaseSync(filename);
  db.exec(
    "CREATE TABLE keep(value);INSERT INTO keep VALUES(42);PRAGMA user_version=99",
  );
  db.close();
  const newer = f.open();
  await newer.init();
  await assert.rejects(
    newer.patch("updates", { autoCheck: false }),
    /preserved/,
  );
  const read = new DatabaseSync(filename, { readOnly: true });
  assert.equal(read.prepare("SELECT value FROM keep").get().value, 42);
  read.close();
});
