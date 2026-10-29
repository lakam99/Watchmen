const { _electron: electron } = require("playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
(async () => {
  await fs.mkdir("test-results", { recursive: true });
  const env = { ...process.env };
  delete env.ELECTRON_RUN_AS_NODE;
  env.WATCHMEN_WORKSPACE_DIR = path.join(
    process.cwd(),
    "test-results",
    "standard-smoke-workspace",
  );
  const executablePath = process.argv.includes("--packaged")
    ? path.join(
        process.cwd(),
        "release",
        require("../package.json").version,
        "Watchmen-win32-x64",
        "Watchmen.exe",
      )
    : undefined;
  const application = await electron.launch({
    timeout:60000,
    ...(executablePath
      ? { executablePath, args: [] }
      : { args: [process.cwd()] }),
    env,
  });
  const errors = [];
  try {
    const page = await application.firstWindow();
    page.on("pageerror", (e) => errors.push(e.message));
    await page.waitForFunction(() => document.querySelector("tbody tr"), {
      timeout: 30000,
    });
    const initial = await page.evaluate(() => window.watchmen.getStatus());
    assert.ok(initial.flows.length > 0, "Real Windows flows must be present");
    assert.equal(initial.locationsEnabled, false);
    assert.equal(initial.agentError, null);
    await page
      .getByRole("button", { name: "Destinations", exact: true })
      .first()
      .click();
    await page.getByRole("button", { name: "Countries", exact: true }).click();
    assert.ok(
      (await page
        .getByRole("row", {
          name: /Unresolved|Local network|Listening endpoints/,
        })
        .count()) > 0,
    );
    await page
      .getByRole("button", { name: "Applications", exact: true })
      .last()
      .click();
    await page
      .getByRole("textbox", { name: "Search traffic" })
      .fill("watchmen-no-such-app-827193");
    await page.getByText("No connections match this view.").waitFor();
    await page.getByRole("button", { name: "Reset filters" }).click();
    await page.locator("tbody tr").first().click();
    await page
      .getByRole("table", { name: "Individual connections" })
      .getByRole("row")
      .nth(1)
      .click();
    await page.getByRole("dialog", { name: "Connection inspector" }).waitFor();
    assert.equal(
      await page.getByRole("combobox", { name: "Inspect connection" }).count(),
      0,
    );
    assert.ok(await page.getByText("Remote IP", { exact: true }).isVisible());
    await page.keyboard.press("Escape");
    await page.getByRole("button", { name: "Settings & privacy" }).click();
    assert.equal(
      await page
        .getByRole("button", { name: "IP location lookup", exact: true })
        .getAttribute("aria-pressed"),
      "false",
    );
    await page.getByRole("button", { name: "Back to my network" }).click();
    await page.getByRole("button", { name: "Pause view", exact: true }).click();
    const frozen = await page.locator(".table-footer").innerText();
    await new Promise((r) => setTimeout(r, 1500));
    assert.equal(await page.locator(".table-footer").innerText(), frozen);
    await page.getByRole("button", { name: "Resume", exact: true }).click();
    const exportPath = path.join(
      process.cwd(),
      "test-results",
      "export-smoke.json",
    );
    await application.evaluate(({ dialog }, filePath) => {
      dialog.showSaveDialog = async () => ({ canceled: false, filePath });
    }, exportPath);
    await page
      .getByRole("button", { name: "Export session", exact: true })
      .click();
    await page.getByText("Session exported.", { exact: true }).waitFor();
    const exported = JSON.parse(await fs.readFile(exportPath, "utf8"));
    assert.ok(exported.flows.length > 0);
    await fs.unlink(exportPath);
    await page.getByRole("button", { name: "Overview", exact: true }).click();
    await page
      .getByRole("combobox", { name: "Connection activity" })
      .selectOption("active");
    await page.getByRole("button", { name: "Dismiss message" }).click();
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.screenshot({
      path: "test-results/overview.png",
      fullPage: true,
    });
    const firstGroup = page
      .locator(
        ".activity-card > .table-scroll > table > tbody > tr[aria-expanded]",
      )
      .first();
    if ((await firstGroup.getAttribute("aria-expanded")) !== "true")
      await firstGroup.click();
    await page
      .getByRole("table", { name: "Individual connections" })
      .getByRole("row")
      .nth(1)
      .click();
    await page.screenshot({
      path: "test-results/inspector.png",
      fullPage: true,
    });
    await page.keyboard.press("Escape");
    await page.getByRole("button", { name: "Settings & privacy" }).click();
    await page.screenshot({
      path: "test-results/settings.png",
      fullPage: true,
    });
    await page.getByRole("button", { name: "Back to my network" }).click();
    await page.setViewportSize({ width: 1000, height: 760 });
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth > window.innerWidth,
      ),
      false,
      "No page-level overflow at minimum width",
    );
    assert.deepEqual(errors, []);
    const result = {
      passed: true,
      packaged: !!executablePath,
      flows: initial.flows.length,
      tracing: initial.tracing,
      checks: [
        "real collector connection",
        "group by destination and country",
        "search and reset",
        "inspector and Escape",
        "privacy default",
        "pause and resume",
        "JSON export",
        "minimum window width",
        "no renderer exceptions",
      ],
    };
    await fs.writeFile(
      "test-results/" +
        (executablePath ? "packaged-smoke" : "ui-smoke") +
        ".json",
      JSON.stringify(result, null, 2),
    );
    console.log(JSON.stringify(result, null, 2));
  } finally {
    await application.close();
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
