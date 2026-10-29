const { _electron: electron } = require("playwright"),
  fs = require("node:fs/promises"),
  path = require("node:path"),
  assert = require("node:assert/strict");
async function waitForIPC(read, predicate) {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    if (predicate(await read())) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("The expected persisted IPC state was not reached.");
}
(async () => {
  await fs.mkdir("test-results", { recursive: true });
  const seed = process.argv.indexOf("--seed"),
    workspace =
      seed >= 0
        ? process.argv[seed + 1]
        : await fs.mkdtemp(
            path.join(
              require("node:os").tmpdir(),
              "watchmen-settings-changes-",
            ),
          );
  if (seed >= 0) {
    const { TrafficStore } = require("../electron/traffic-store.cjs");
    let now = Date.now() - 180000;
    const store = new TrafficStore(
        path.join(workspace, ".watchmen/traffic.sqlite"),
        { clock: () => now, sessionId: "settings-changes-fixture" },
      ),
      base = {
        id: "base",
        app: "Change Group Fixture",
        processPath: "C:/WatchmenFixtures/Group.exe",
        pid: 9001,
        protocol: "TCP",
        remoteAddress: "8.8.8.8",
        remotePort: 443,
        localAddress: "192.0.2.2",
        localPort: 51000,
        state: "Established",
        active: true,
        received: 0,
        sent: 0,
        firstSeen: new Date(now).toISOString(),
      };
    const ingest = (flows) =>
      store.ingest({
        timestamp: new Date(now).toISOString(),
        startedAt: base.firstSeen,
        tracing: false,
        eventsLost: 0,
        flows,
      });
    ingest([base]);
    for (let i = 0; i < 65; i++) {
      now += 2000;
      ingest([base]);
    }
    now += 2000;
    ingest(
      Array.from({ length: 80 }, (_, i) => ({
        ...base,
        id: "new-" + i,
        remoteAddress: "203.0.113." + (i + 1),
        firstSeen: new Date(now).toISOString(),
      })),
    );
    store.close();
    await fs.writeFile(
      path.join(workspace, ".watchmen/settings.json"),
      JSON.stringify({
        theme: "dark",
        ai: {
          provider: "openrouter",
          baseUrl: "https://openrouter.ai/api/v1",
          model: "fixture/model",
        },
      }),
    );
    await fs.writeFile(
      path.join(workspace, ".watchmen/update-settings.json"),
      JSON.stringify({ autoCheck: false, autoDownload: false }),
    );
    return;
  }
  require("node:child_process").execFileSync(
    process.execPath,
    [__filename, "--seed", workspace],
    { stdio: "pipe" },
  );
  const packaged = process.argv.includes("--packaged"),
    env = { ...process.env, WATCHMEN_WORKSPACE_DIR: workspace };
  delete env.ELECTRON_RUN_AS_NODE;
  const launch = () =>
    electron.launch({
      ...(packaged
        ? {
            executablePath: path.resolve(
              "release",
              require("../package.json").version,
              "Watchmen-win32-x64/Watchmen.exe",
            ),
            args: ["--user-data-dir=" + path.join(workspace, "chromium")],
          }
        : {
            args: [
              process.cwd(),
              "--user-data-dir=" + path.join(workspace, "chromium"),
            ],
          }),
      env,
      timeout: 60000,
    });
  let app = await launch(),
    page;
  const errors = [];
  async function window() {
    page = await app.firstWindow({ timeout: 60000 });
    page.on("pageerror", (error) => errors.push(error.message));
    await page.waitForFunction(() => window.watchmen);
    await page.waitForFunction(
      () => document.documentElement.dataset.theme === "dark",
    );
  }
  try {
    await window();
    await page
      .getByRole("navigation")
      .getByRole("button", { name: "Destinations", exact: true })
      .click();
    await page
      .getByRole("combobox", { name: "Network scope", exact: true })
      .selectOption("internet");
    await page
      .getByRole("textbox", { name: "Search traffic", exact: true })
      .fill("remember-my-filter");
    await waitForIPC(
      () => page.evaluate(() => window.watchmen.viewSettings()),
      (r) =>
        r.ok &&
        r.value.page === "Destinations" &&
        r.value.filter === "internet" &&
        r.value.search === "remember-my-filter",
    );
    await app.close();
    app = await launch();
    await window();
    await page.waitForFunction(
      () =>
        document.querySelector('[aria-label="Search traffic"]')?.value ===
        "remember-my-filter",
    );
    assert.equal(
      await page
        .getByRole("textbox", { name: "Search traffic", exact: true })
        .inputValue(),
      "remember-my-filter",
    );
    assert.equal(
      await page
        .getByRole("combobox", { name: "Network scope", exact: true })
        .inputValue(),
      "internet",
    );
    await page
      .getByRole("button", { name: "Clear search", exact: true })
      .click();
    await page
      .getByRole("navigation")
      .getByRole("button", { name: "Overview", exact: true })
      .click();
    await page.getByRole("button", { name: "Pause view", exact: true }).click();
    await page
      .getByRole("navigation")
      .getByRole("button", { name: "Changes", exact: true })
      .click();
    const changes = page.getByRole("table", {
      name: "Saved connection changes",
      exact: true,
    });
    await changes
      .getByRole("row", {
        name: "Review New destination for Change Group Fixture",
        exact: true,
      })
      .waitFor();
    assert.equal(await changes.locator("tbody tr").count(), 1);
    await changes
      .getByText("80 new observations grouped", { exact: true })
      .waitFor();
    await page.screenshot({ path: "test-results/grouped-changes-dark.png" });
    await page
      .getByRole("button", { name: "Mark all reviewed", exact: true })
      .click();
    await waitForIPC(
      () =>
        page.evaluate(() =>
          window.watchmen.alertsList({
            status: "open",
            type: "all",
            search: "",
          }),
        ),
      (r) => r.ok && r.value.counts.open === 0,
    );
    await page.locator(".change-count").waitFor({ state: "detached" });
    await page
      .getByRole("combobox", { name: "Change status", exact: true })
      .selectOption("dismissed");
    await changes
      .getByRole("row", {
        name: "Review New destination for Change Group Fixture",
        exact: true,
      })
      .waitFor();
    assert.deepEqual(errors, []);
    const verification = await app.evaluate(
      async ({ app }, { workspace }) => {
        const require = process
            .getBuiltinModule("module")
            .createRequire(app.getAppPath() + "/electron/main.cjs"),
          { DatabaseSync } = require("node:sqlite"),
          db = new DatabaseSync(workspace + "/.watchmen/traffic.sqlite", {
            readOnly: true,
          });
        try {
          return {
            settingsRows: db
              .prepare("SELECT key FROM app_settings ORDER BY key")
              .all()
              .map((row) => row.key),
            storedTheme: JSON.parse(
              db
                .prepare(
                  "SELECT value_json FROM app_settings WHERE key='preferences'",
                )
                .get().value_json,
            ).theme,
          };
        } finally {
          db.close();
        }
      },
      { workspace },
    );
    assert.equal(verification.storedTheme, "dark");
    assert.deepEqual(verification.settingsRows, [
      "monitor",
      "preferences",
      "updates",
      "window",
    ]);
    const result = {
      passed: true,
      packaged,
      checks: [
        "JSON-to-SQLite preference migration",
        "monitor page/filter/search after restart",
        "80 new IPs represented as one review group",
        "mark all reviewed clears badge even while view is paused",
        "reviewed history retained",
        "four settings namespaces in local SQLite",
        "no renderer errors",
      ],
    };
    await fs.writeFile(
      "test-results/settings-changes-smoke" +
        (packaged ? "-packaged" : "") +
        ".json",
      JSON.stringify(result, null, 2),
    );
    console.log(JSON.stringify(result, null, 2));
  } finally {
    await app.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
