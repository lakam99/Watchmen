const { _electron: electron } = require("playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");
(async () => {
  await fs.mkdir("test-results", { recursive: true });
  const workspace = await fs.mkdtemp(
    path.join(process.cwd(), "test-results", "profile-workspace-"),
  );
  const env = { ...process.env, WATCHMEN_WORKSPACE_DIR: workspace };
  delete env.ELECTRON_RUN_AS_NODE;
  const packaged = process.argv.includes("--packaged");
  const executablePath = path.join(
    process.cwd(),
    "release",
    require("../package.json").version,
    "Watchmen-win32-x64",
    "Watchmen.exe",
  );
  const launch = () =>
    electron.launch({
      ...(packaged ? { executablePath, args: [] } : { args: [process.cwd()] }),
      env,
    });
  const errors = [];
  const waitForProfile = async (page, condition) => {
    const deadline = Date.now() + 30000;
    while (Date.now() < deadline) {
      const result = await page.evaluate(() =>
        window.watchmen.trafficProfile({ range: "all" }),
      );
      if (result.ok && condition(result.value)) return result;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error(
      "Timed out waiting for the committed traffic profile state.",
    );
  };
  let first = await launch(),
    second;
  const ready = async (app) => {
    const page = await app.firstWindow();
    page.on("pageerror", (e) => errors.push(e.message));
    await waitForProfile(page, (value) => value.totals.applications > 0);
    return page;
  };
  try {
    let page = await ready(first);
    const initial = await page.evaluate(() =>
      window.watchmen.trafficProfile({ range: "all" }),
    );
    assert.equal(initial.ok, true);
    const saved = initial.value.applications[0];
    assert.ok(saved.id);
    assert.equal(initial.value.totals.measuredMs, 0);
    assert.equal(initial.value.totals.received, 0);
    await page
      .getByRole("button", { name: "Traffic profile", exact: true })
      .click();
    await page
      .getByRole("table", { name: "Saved application profiles" })
      .waitFor();
    await page
      .getByRole("row", { name: `Saved profile ${saved.name}`, exact: true })
      .click();
    await page
      .getByRole("table", { name: "Saved application services" })
      .waitFor();
    assert.ok(
      (await page
        .getByRole("table", { name: "Saved application services" })
        .getByRole("row")
        .count()) > 1,
    );
    await page
      .getByRole("textbox", { name: "Search saved profiles" })
      .fill("impossible-cached-application-831994");
    await page.getByText("No saved profiles match.", { exact: true }).waitFor();
    await page.getByRole("textbox", { name: "Search saved profiles" }).fill("");
    await page
      .getByRole("combobox", { name: "Profile time range" })
      .selectOption("7d");
    await page
      .getByRole("button", { name: "Destination profiles", exact: true })
      .click();
    await page
      .getByRole("table", { name: "Saved destination profiles" })
      .waitFor();
    const snapshot = await page.evaluate(() => window.watchmen.getStatus());
    const preview = await page.evaluate(
      (ids) =>
        window.watchmen.previewInsights({ flowIds: ids, includeIPs: false }),
      snapshot.flows
        .filter((f) => f.active)
        .slice(0, 100)
        .map((f) => f.id),
    );
    assert.ok(preview.ok);
    assert.ok(preview.value.payload.savedApplicationProfiles.length > 0);
    assert.equal(
      JSON.stringify(preview.value.payload.savedApplicationProfiles).includes(
        "processPath",
      ),
      false,
    );
    await first.close();
    first = await launch();
    page = await ready(first);
    await waitForProfile(
      page,
      (value) => value.totals.sessions > initial.value.totals.sessions,
    );
    const reopened = await page.evaluate(() =>
      window.watchmen.trafficProfile({ range: "all" }),
    );
    const detail = await page.evaluate(
      (appId) => window.watchmen.trafficProfileApp({ appId, range: "all" }),
      saved.id,
    );
    assert.ok(detail.ok && detail.value.application.id === saved.id);
    assert.ok(
      reopened.value.totals.observations >= initial.value.totals.observations,
    );
    second = await launch();
    const other = await ready(second);
    const a = await page.evaluate(() =>
        window.watchmen.trafficProfile({ range: "all" }),
      ),
      b = await other.evaluate(() =>
        window.watchmen.trafficProfile({ range: "all" }),
      );
    assert.equal(a.value.recording, true);
    assert.equal(b.value.recording, false);
    assert.equal(
      b.value.totals.sessions,
      a.value.totals.sessions,
      "Standby window must not create a duplicate recording session",
    );
    await first.close();
    first = null;
    const handed = await waitForProfile(
      other,
      (value) =>
        value.recording && value.totals.sessions > a.value.totals.sessions,
    );
    assert.ok(handed.value.totals.sessions > a.value.totals.sessions);
    await other.getByRole("button", { name: "Settings & privacy" }).click();
    await other.getByRole("button", { name: "Dark", exact: true }).click();
    await other.getByRole("button", { name: "Back to my network" }).click();
    await other
      .getByRole("button", { name: "Traffic profile", exact: true })
      .click();
    await other
      .getByRole("table", { name: "Saved application profiles" })
      .waitFor();
    await other.setViewportSize({ width: 1440, height: 1050 });
    await other.screenshot({
      path: "test-results/traffic-profile-dark.png",
      fullPage: true,
    });
    await other
      .getByRole("table", { name: "Saved application profiles" })
      .getByRole("row")
      .nth(1)
      .click();
    await other
      .getByRole("table", { name: "Saved application services" })
      .waitFor();
    await other.screenshot({
      path: "test-results/traffic-profile-services-dark.png",
    });
    await other.setViewportSize({ width: 1000, height: 760 });
    assert.equal(
      await other.evaluate(
        () => document.documentElement.scrollWidth > innerWidth,
      ),
      false,
    );
    await second.close();
    second = null;
    const db = new DatabaseSync(
      path.join(workspace, ".watchmen", "traffic.sqlite"),
    );
    const health = db.prepare("PRAGMA quick_check").get().quick_check;
    assert.equal(health, "ok");
    const cursors = db
      .prepare("SELECT COUNT(*) count FROM flow_cursors")
      .get().count;
    assert.ok(cursors > 0);
    db.close();
    assert.deepEqual(errors, []);
    const result = {
      passed: true,
      packaged,
      databaseIntegrity: health,
      initialApplications: initial.value.totals.applications,
      initialDestinations: initial.value.totals.destinations,
      recordingSessions: handed.value.totals.sessions,
      retainedConnectionRecords: cursors,
      checks: [
        "live collector ingestion",
        "application and destination profile UI",
        "saved service drilldown",
        "profile search and time range",
        "unknown byte coverage in ordinary mode",
        "history survives restart",
        "stable app identity across restart",
        "single shared recorder across simultaneous windows",
        "recorder handoff",
        "historical AI summaries without executable paths",
        "minimum width",
        "no renderer exceptions",
      ],
    };
    await fs.writeFile(
      "test-results/profile-smoke" + (packaged ? "-packaged" : "") + ".json",
      JSON.stringify(result, null, 2),
    );
    console.log(JSON.stringify(result, null, 2));
  } finally {
    await first?.close();
    await second?.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
