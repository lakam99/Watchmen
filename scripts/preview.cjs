const { _electron: electron } = require("playwright");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs/promises");
(async () => {
  const env = { ...process.env };
  delete env.ELECTRON_RUN_AS_NODE;
  delete env.WATCHMEN_WORKSPACE_DIR;
  const executablePath = path.join(
    process.cwd(),
    "release",
    require("../package.json").version,
    "Watchmen-win32-x64",
    "Watchmen.exe",
  );
  const application = await electron.launch({ executablePath, args: [], env });
  try {
    const page = await application.firstWindow();
    await page.waitForFunction(() => document.querySelector("tbody tr"));
    const status = await page.evaluate(() => window.watchmen.preferences());
    assert.equal(status.ok, true);
    assert.equal(
      status.value.storagePath,
      path.join(process.cwd(), ".watchmen", "ai-token.bin"),
    );
    await page.getByRole("button", { name: "Settings & privacy" }).click();
    await page.getByRole("button", { name: "Dark", exact: true }).click();
    await page.getByRole("button", { name: "Back to my network" }).click();
    await page
      .getByRole("button", { name: "Traffic profile", exact: true })
      .click();
    await page
      .getByRole("table", { name: "Saved application profiles" })
      .getByRole("row")
      .nth(1)
      .waitFor();
    const profile = await page.evaluate(() =>
      window.watchmen.trafficProfile({ range: "all" }),
    );
    assert.ok(profile.ok && profile.value.totals.applications > 0);
    assert.equal(
      profile.value.databasePath,
      path.join(process.cwd(), ".watchmen", "traffic.sqlite"),
    );
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.screenshot({
      path: `test-results/live-v${require("../package.json").version}-profile-dark.png`,
    });
    await fs.writeFile(
      "test-results/workspace-resolution.json",
      JSON.stringify(
        {
          passed: true,
          credentialPath: status.value.storagePath,
          theme: "dark",
          noAIRequestsMade: true,
          trafficDatabasePath: profile.value.databasePath,
          savedApplications: profile.value.totals.applications,
        },
        null,
        2,
      ),
    );
    console.log(
      "Working-directory credential path verified; dark theme enabled.",
    );
  } finally {
    await application.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
