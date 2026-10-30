const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs/promises"),
  path = require("node:path"),
  os = require("node:os");
const { SettingsStore } = require("../electron/settings-store.cjs"),
  { TrafficStore } = require("../electron/traffic-store.cjs"),
  { AppResearchCache } = require("../electron/app-research-cache.cjs"),
  { RowOverview } = require("../electron/row-overview.cjs");
const config = {
  provider: "openrouter",
  baseUrl: "https://openrouter.ai/api/v1",
  model: "fixture",
  token: "synthetic-cache-secret",
};
const record = (app = "Chrome", n = 1) => ({
  app,
  status: "completed",
  text: `App purpose ${n}`,
  researchedAt: new Date(1700000000000 + n * 1000).toISOString(),
  sources: [{ url: `https://example.com/app/${n}`, title: `Source ${n}` }],
});
async function fixture(t, { limit = 500 } = {}) {
  const directory = await fs.mkdtemp(
      path.join(os.tmpdir(), "watchmen-research-db-"),
    ),
    stores = [];
  let now = 1700000000000;
  const open = async () => {
    const settings = new SettingsStore(directory);
    await settings.init();
    stores.push(settings);
    return {
      settings,
      cache: new AppResearchCache(settings.db, { limit, clock: () => ++now }),
    };
  };
  const f = await open();
  t.after(async () => {
    for (const s of stores) s.close();
    await fs.rm(directory, { recursive: true, force: true });
  });
  return { ...f, open, directory };
}
const row = {
  id: "cache-row",
  kind: "connection",
  label: "private row label",
  facts: { app: "Chrome", protocol: "TCP", remotePort: 443, received: 9999 },
};
function manager(
  cache,
  {
    provider = "openrouter",
    auto = false,
    failBase = false,
    failWeb = false,
  } = {},
) {
  const requests = [],
    cfg = {
      ...config,
      provider,
      baseUrl:
        provider === "openai"
          ? "https://api.openai.com/v1"
          : "https://openrouter.ai/api/v1",
    };
  let count = 0,
    webFailure = failWeb,
    baseFailure = failBase,
    hold = null;
  const overview = new RowOverview(
    { credential: async () => cfg },
    async (_, init) => {
      const body = JSON.parse(init.body),
        web = body.tools?.some((t) =>
          ["web_search", "openrouter:web_search"].includes(t.type),
        );
      requests.push({ web, body });
      if ((web && webFailure) || (!web && baseFailure))
        return new Response("untrusted provider error", { status: 429 });
      if (web && hold) return new Promise((resolve) => hold(resolve));
      const n = web ? ++count : 0,
        text = web ? `Researched purpose ${n}` : "Fresh row explanation",
        citation = {
          type: "url_citation",
          url: `https://example.com/app/${n}`,
          title: `Source ${n}`,
        };
      return new Response(
        JSON.stringify(
          provider === "openai"
            ? {
                status: "completed",
                output: [
                  ...(web
                    ? [
                        {
                          type: "web_search_call",
                          status: "completed",
                          action: { type: "search" },
                        },
                      ]
                    : []),
                  {
                    type: "message",
                    role: "assistant",
                    content: [
                      {
                        type: "output_text",
                        text,
                        annotations: web ? [citation] : [],
                      },
                    ],
                  },
                ],
              }
            : {
                choices: [
                  {
                    message: {
                      content: text,
                      annotations: web
                        ? [{ type: "url_citation", url_citation: citation }]
                        : [],
                    },
                  },
                ],
              },
        ),
      );
    },
    { cache, webSearchAllowed: () => auto },
  );
  return {
    overview,
    requests,
    failWeb: (v) => (webFailure = v),
    failBase: (v) => (baseFailure = v),
    holdWeb: (f) => (hold = f),
    webCount: () => requests.filter((r) => r.web).length,
  };
}
test("research persists in the existing traffic database across restart and uses normalized names without merging distinct apps", async (t) => {
  const f = await fixture(t);
  assert.equal(f.cache.put("Chrome", record(), config), true);
  const reopened = await f.open(),
    hit = reopened.cache.get(" CHROME.exe ");
  assert.equal(hit.cached, true);
  assert.equal(hit.text, "App purpose 1");
  assert.equal(hit.provider, "openrouter");
  assert.equal(hit.researchedAt, record().researchedAt);
  assert.equal(reopened.cache.get("Firefox"), null);
  const traffic = new TrafficStore(f.settings.path);
  assert.equal(traffic.db.prepare("PRAGMA user_version").get().user_version, 2);
  traffic.close();
  assert.ok(reopened.cache.get("chrome"));
});
test("instances share successful records atomically and refresh overwrites the same app without storing credentials or row facts", async (t) => {
  const f = await fixture(t),
    other = await f.open();
  const data = {
    ...record(),
    text: `App ${config.token}`,
    payloadText: "private packet",
    remoteIP: "10.0.0.1",
    path: "C:\\Private",
    facts: row.facts,
  };
  assert.equal(f.cache.put("Chrome", data, config), true);
  assert.equal(other.cache.get("chrome").text, "App [redacted]");
  assert.equal(
    other.cache.put("Chrome.exe", record("Chrome", 2), config),
    true,
  );
  assert.equal(f.cache.get("Chrome").text, "App purpose 2");
  const stored = f.settings.db
    .prepare("SELECT * FROM app_research_cache")
    .all();
  assert.equal(stored.length, 1);
  const json = JSON.stringify(stored);
  for (const secret of [
    config.token,
    "10.0.0.1",
    "private packet",
    "Private",
    "9999",
    "remoteIP",
    "payloadText",
  ])
    assert.ok(!json.includes(secret), secret);
});
test("malformed and future cache schemas are preserved, invalid entries are ignored, and writes fail nonfatally", async (t) => {
  const f = await fixture(t);
  assert.equal(f.cache.put("Chrome", record(), config), true);
  f.settings.db
    .prepare("UPDATE app_research_cache SET result_json=?")
    .run("not JSON");
  assert.equal(f.cache.get("Chrome"), null);
  assert.equal(
    f.cache.put(
      "Chrome",
      {
        ...record(),
        sources: [{ url: "https://10.0.0.1/secret", title: "private" }],
      },
      config,
    ),
    false,
  );
  assert.equal(f.cache.put("C:\\Private", record(), config), false);
  f.settings.db.exec("UPDATE app_research_schema SET version=2");
  const future = new AppResearchCache(f.settings.db);
  assert.equal(future.available, false);
  assert.equal(future.put("Chrome", record(), config), false);
  assert.equal(
    f.settings.db.prepare("SELECT result_json FROM app_research_cache").get()
      .result_json,
    "not JSON",
  );
});
test("cache retention keeps frequently used research and never grows beyond its record bound", async (t) => {
  const f = await fixture(t, { limit: 2 });
  f.cache.put("Alpha", record("Alpha"), config);
  f.cache.put("Beta", record("Beta"), config);
  f.cache.get("Alpha");
  f.cache.put("Gamma", record("Gamma"), config);
  assert.equal(f.cache.get("Beta"), null);
  assert.ok(f.cache.get("Alpha"));
  assert.ok(f.cache.get("Gamma"));
  assert.equal(
    f.settings.db.prepare("SELECT COUNT(*) n FROM app_research_cache").get().n,
    2,
  );
});
test("repeated overviews reuse app research even with web permission off while live row analysis stays fresh", async (t) => {
  const f = await fixture(t),
    m = manager(f.cache);
  const initial = await m.overview.researchApp(row);
  assert.equal(initial.research.cached, false);
  assert.equal(m.webCount(), 1);
  for (const kind of ["connection", "profile_app", "packet"]) {
    const r = await m.overview.explain({
      ...row,
      id: kind,
      kind,
      facts: { app: "chrome.exe", received: 123 },
    });
    assert.equal(r.research.cached, true);
    assert.equal(r.text, "Fresh row explanation");
    assert.equal(r.research.researchedAt, initial.research.researchedAt);
    assert.ok(m.overview.hasSource(initial.research.sources[0].url));
  }
  assert.equal(m.webCount(), 1);
  assert.equal(m.requests.filter((r) => !r.web).length, 3);
  const restarted = manager((await f.open()).cache, {
    provider: "openai",
    auto: true,
  });
  const reused = await restarted.overview.explain(row);
  assert.equal(restarted.webCount(), 0);
  assert.equal(reused.research.provider, "openrouter");
  assert.equal(reused.research.cached, true);
});
test("explicit refresh runs one new lookup, replaces saved findings and citations, and validates refresh arguments", async (t) => {
  const f = await fixture(t),
    m = manager(f.cache);
  const initial = await m.overview.researchApp(row),
    refreshed = await m.overview.researchApp({
      ...row,
      id: "refresh",
      refresh: true,
    });
  assert.equal(m.webCount(), 2);
  assert.equal(refreshed.research.cached, false);
  assert.equal(refreshed.research.text, "Researched purpose 2");
  assert.equal(m.overview.hasSource(initial.research.sources[0].url), false);
  assert.equal(f.cache.get("Chrome").text, refreshed.research.text);
  const hit = await m.overview.explain(row);
  assert.equal(hit.research.cached, true);
  assert.equal(m.webCount(), 2);
  await assert.rejects(
    () => m.overview.researchApp({ ...row, refresh: "yes" }),
    /Invalid/,
  );
  await assert.rejects(
    () => m.overview.explain({ ...row, refresh: true }),
    /refresh action/,
  );
});
test("failed or cancelled refresh retains good cached findings and collection date without late writes", async (t) => {
  const f = await fixture(t),
    m = manager(f.cache);
  const first = await m.overview.researchApp(row);
  m.failWeb(true);
  const failed = await m.overview.researchApp({
    ...row,
    id: "failed",
    refresh: true,
  });
  assert.equal(failed.research.status, "completed");
  assert.equal(failed.research.cached, true);
  assert.equal(failed.research.researchedAt, first.research.researchedAt);
  assert.match(failed.research.notice, /previously saved/);
  assert.equal(f.cache.get("Chrome").text, first.research.text);
  m.failWeb(false);
  let release;
  m.holdWeb((r) => (release = r));
  const pending = m.overview.researchApp({
    ...row,
    id: "cancelled",
    refresh: true,
  });
  while (!release) await new Promise(setImmediate);
  m.overview.cancel("cancelled");
  release(
    new Response(
      JSON.stringify({
        choices: [
          {
            message: {
              content: "Late result",
              annotations: [
                {
                  type: "url_citation",
                  url_citation: {
                    url: "https://example.com/late",
                    title: "Late",
                  },
                },
              ],
            },
          },
        ],
      }),
    ),
  );
  await assert.rejects(() => pending, /canceled or timed out/);
  assert.equal(f.cache.get("Chrome").text, first.research.text);
  // Cancellation during the final asynchronous context check must precede persistence.
  m.holdWeb(null);
  let finalCheck;
  let checks = 0;
  const target = m.webCount() + 1,
    credential = m.overview.preferences.credential;
  m.overview.preferences.credential = async () => {
    const cfg = await credential();
    if (m.webCount() === target && ++checks === 2)
      await new Promise((r) => (finalCheck = r));
    return cfg;
  };
  const atCommit = m.overview.researchApp({
    ...row,
    id: "cancel-at-commit",
    refresh: true,
  });
  while (!finalCheck) await new Promise(setImmediate);
  m.overview.cancel("cancel-at-commit");
  finalCheck();
  await assert.rejects(() => atCommit, /canceled or timed out/);
  assert.equal(f.cache.get("Chrome").text, first.research.text);
});
test("a provider outage can show saved research and a database write failure never masquerades as a saved cache hit", async (t) => {
  const f = await fixture(t),
    m = manager(f.cache);
  await m.overview.researchApp(row);
  m.failBase(true);
  const offline = await m.overview.explain(row);
  assert.match(offline.overviewNotice, /rate limit/);
  assert.equal(offline.research.cached, true);
  assert.equal(m.webCount(), 1);
  const other = manager(f.cache);
  f.settings.db.exec("PRAGMA query_only=ON");
  const fresh = await other.overview.researchApp({
    ...row,
    facts: { app: "Firefox" },
  });
  assert.equal(fresh.research.status, "completed");
  assert.equal(fresh.research.cached, false);
  assert.match(fresh.research.cacheNotice, /could not be saved/);
  assert.equal(f.cache.get("Firefox"), null);
  f.settings.db.exec("PRAGMA query_only=OFF");
});
