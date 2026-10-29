const { _electron: electron } = require("playwright");
const fs = require("node:fs/promises");
const path = require("node:path");
const assert = require("node:assert/strict");
(async () => {
  await fs.mkdir("test-results", { recursive: true });
  const workspace = await fs.mkdtemp(
    path.join(process.cwd(), "test-results", "rules-ui-"),
  );
  const packaged = process.argv.includes("--packaged");
  const env = { ...process.env, WATCHMEN_WORKSPACE_DIR: workspace };
  delete env.ELECTRON_RUN_AS_NODE;
  const launch = () =>
    electron.launch({
      ...(packaged
        ? {
            executablePath: path.join(
              process.cwd(),
              "release",
              require("../package.json").version,
              "Watchmen-win32-x64",
              "Watchmen.exe",
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
  let application = await launch();
  const errors = [];
  let page;
  async function installMock(admin = false) {
    page = await application.firstWindow({ timeout: 60000 });
    page.on("pageerror", (error) => errors.push(error.message));
    await page.waitForFunction(() => window.watchmen);
    const snapshot = await page.evaluate(() => window.watchmen.getStatus());
    await application.evaluate(
      async (
        { app, ipcMain, BrowserWindow },
        { workspace, snapshot, admin },
      ) => {
        const require = process
          .getBuiltinModule("module")
          .createRequire(app.getAppPath() + "/electron/main.cjs");
        const fs = require("node:fs");
        const path = require("node:path");
        const { randomUUID } = require("node:crypto");
        const { Firewall } = require(
          path.join(app.getAppPath(), "electron", "firewall.cjs"),
        );
        const filename = path.join(workspace, "mock-windows-policies.json");
        let saved = [];
        try {
          saved = JSON.parse(fs.readFileSync(filename, "utf8"));
        } catch {}
        const state = {
          rules: saved,
          admin,
          profiles: [
            { profile: 1, enabled: true },
            { profile: 2, enabled: true },
            { profile: 4, enabled: true },
          ],
          isolationVerified: true,
          verificationError: null,
          updatedAt: new Date().toISOString(),
        };
        const flow = {
          id: "rule-ui-fixture",
          app: "Watchmen Rule Test",
          processPath: "C:\\WatchmenFixtures\\RuleTest.exe",
          pid: 4242,
          protocol: "TCP",
          localAddress: "192.0.2.2",
          localPort: 52000,
          remoteAddress: "203.0.113.7",
          remotePort: 443,
          state: "Established",
          active: true,
          received: 2048,
          sent: 1024,
          rxRate: 0,
          txRate: 0,
          firstSeen: new Date().toISOString(),
          lastSeen: new Date().toISOString(),
        };
        global.__ruleSnapshot = {
          ruleUiFixture: true,
          ...snapshot,
          admin,
          tracing: false,
          traceError: null,
          agentError: null,
          eventsLost: 0,
          errors: [],
          evictedFlows: 0,
          flows: [flow],
          locationsEnabled: true,
          locations: {
            "203.0.113.7": {
              country: "Canada",
              code: "CA",
              city: "Test fixture",
              org: "Synthetic test network",
            },
          },
          profileStatus: undefined,
        };
        global.__nativeActions = [];
        const manager = new Firewall(path.join(workspace, ".watchmen"), {
          snapshot: () => global.__ruleSnapshot,
          transport: async (request, options) => {
            if (request.action !== "list" && global.__holdRuleTask) {
              options.onProgress({
                type: "progress",
                stage: "staging",
                message: "Staging persistent Windows filters...",
                completed: 500,
                total: 2000,
                canCancel: true,
                lastAdvancedAt: new Date().toISOString(),
              });
              await new Promise((resolve, reject) => {
                global.__finishRuleTask = resolve;
                options.signal.addEventListener("abort", () => {
                  const error = new Error(
                    "Rule change cancelled. The uncommitted transaction was rolled back.",
                  );
                  error.cancelled = true;
                  reject(error);
                });
              });
              options.onProgress({
                type: "progress",
                stage: "committing",
                message: "Committing Windows rules...",
                completed: 0,
                total: 0,
                canCancel: false,
                lastAdvancedAt: new Date().toISOString(),
              });
            }
            if (request.action !== "list") {
              global.__nativeActions.push(request.action);
              await new Promise((resolve) => setTimeout(resolve, 80));
            }
            if (request.action === "add") {
              const input = request.rule;
              let found = state.rules.find(
                (r) =>
                  r.kind === input.kind &&
                  r.appPath === input.appPath &&
                  r.address === input.address &&
                  r.port === input.port &&
                  JSON.stringify(r.countries) ===
                    JSON.stringify(input.countries),
              );
              if (input.kind === "onlyApp") {
                state.rules = state.rules.filter((r) => r.kind !== "onlyApp");
                found = null;
              }
              if (found) found.enabled = true;
              else
                state.rules.push({
                  ...input,
                  id:
                    input.kind === "onlyApp"
                      ? "375e9c3b-f765-4404-94cb-0912b6464d15"
                      : randomUUID(),
                  createdAt: new Date().toISOString(),
                  enabled: true,
                  partial: false,
                  nativeRuleCount: ["region", "onlyRegion"].includes(input.kind)
                    ? request.ranges.length * 2
                    : ["app", "onlyApp"].includes(input.kind)
                      ? 4
                      : 2,
                  sourceMonth: input.sourceMonth || "",
                  rangeCount: request.ranges.length,
                });
            } else if (request.action === "set-enabled") {
              const rule = state.rules.find((r) => r.id === request.id);
              rule.enabled = request.enabled;
            } else if (request.action === "forget")
              state.rules = state.rules.filter((r) => r.id !== request.id);
            else if (request.action === "unblock-all")
              state.rules.forEach((r) => (r.enabled = false));
            fs.writeFileSync(filename, JSON.stringify(state.rules));
            return structuredClone(state);
          },
        });
        // UI tests use the production manager/IPC contract with a fake Windows
        // transport. Actual OS enforcement is tested separately by the elevated suite.
        manager.regions.prepare = async (countries) => ({
          countries,
          sourceMonth: "2026-10",
          ranges: ["203.0.113.0-203.0.113.255", "2001:db8::1-2001:db8::ffff"],
          rangeCount: 2,
        });
        global.__ruleManager = manager;
        await manager.refresh();
        const handlers = {
          "firewall-status": (refresh) =>
            refresh ? manager.refresh() : manager.status(),
          "firewall-catalog": () => manager.catalog(),
          "firewall-preview": (input) => manager.prepare(input),
          "firewall-apply": (id) => manager.apply(id),
          "firewall-toggle": (id, enabled) => manager.toggle(id, enabled),
          "firewall-forget": (id) => manager.forget(id),
          "firewall-unblock-all": () => manager.unblockAll(),
          "firewall-cancel": () => manager.cancel(),
          "firewall-pick-app": (only) =>
            manager.prepareExecutable(flow.processPath, flow.app, only),
        };
        for (const [name, handler] of Object.entries(handlers)) {
          ipcMain.removeHandler(name);
          ipcMain.handle(name, async (event, ...args) => {
            if (event.sender !== BrowserWindow.getAllWindows()[0].webContents)
              throw new Error("Untrusted test sender");
            try {
              return { ok: true, value: await handler(...args) };
            } catch (error) {
              return { ok: false, error: error.message };
            }
          });
        }
        const web = BrowserWindow.getAllWindows()[0].webContents;
        const send = web.send.bind(web);
        web.send = (channel, ...args) => {
          if (channel === "snapshot" && !args[0]?.ruleUiFixture) return;
          return send(channel, ...args);
        };
        global.__ruleTimer = setInterval(
          () =>
            BrowserWindow.getAllWindows()[0]?.webContents.send("snapshot", {
              ...global.__ruleSnapshot,
              timestamp: new Date().toISOString(),
            }),
          200,
        );
      },
      { workspace, snapshot, admin },
    );
  }
  try {
    await installMock(false);
    await page
      .getByRole("navigation")
      .getByRole("button", { name: "Applications", exact: true })
      .click();
    await page
      .getByRole("row", {
        name: "Connections for Watchmen Rule Test",
        exact: true,
      })
      .waitFor();
    await page
      .getByRole("button", {
        name: "Block app Watchmen Rule Test",
        exact: true,
      })
      .click();
    await page
      .getByRole("dialog", { name: "Block this application", exact: true })
      .waitFor();
    assert.equal(
      await page
        .getByRole("button", { name: "Block now", exact: true })
        .count(),
      0,
    );
    assert.ok(
      await page
        .getByRole("dialog")
        .getByRole("button", { name: "Restart as administrator" })
        .isVisible(),
    );
    await page.keyboard.press("Escape");
    await page.getByRole("dialog").waitFor({ state: "hidden" });
    assert.deepEqual(
      await application.evaluate(() => global.__nativeActions),
      [],
    );
    await application.evaluate(() => {
      global.__ruleSnapshot.admin = true;
      global.__ruleManager.state.admin = true;
    });
    await page
      .getByRole("button", { name: "Settings & privacy", exact: true })
      .click();
    await page.getByRole("button", { name: "Dark", exact: true }).click();
    await page
      .getByRole("button", { name: "Back to my network", exact: true })
      .click();
    await page
      .getByRole("button", {
        name: "Block app Watchmen Rule Test",
        exact: true,
      })
      .click();
    await page.getByRole("button", { name: "Block now", exact: true }).click();
    await page
      .getByRole("button", {
        name: "Unblock app Watchmen Rule Test",
        exact: true,
      })
      .waitFor();
    const savedApp = await page.evaluate(async () => {
      const r = await window.watchmen.firewallStatus();
      return r.value.rules.find((r) => r.kind === "app");
    });
    assert.equal(savedApp.enabled, true);
    await page
      .getByRole("row", {
        name: "Connections for Watchmen Rule Test",
        exact: true,
      })
      .click();
    await page
      .getByRole("button", {
        name: "Block connection 203.0.113.7",
        exact: true,
      })
      .click();
    await page
      .getByRole("dialog", {
        name: "Block this endpoint for this app",
        exact: true,
      })
      .waitFor();
    assert.ok((await page.getByRole("dialog").innerText()).includes("TCP/443"));
    await page.getByRole("button", { name: "Block now", exact: true }).click();
    await page
      .getByRole("button", {
        name: "Unblock connection 203.0.113.7",
        exact: true,
      })
      .waitFor();
    await page.setViewportSize({ width: 1440, height: 1100 });
    await page.screenshot({
      path: "test-results/table-blocking-dark.png",
      fullPage: true,
    });
    await page
      .getByRole("button", {
        name: "Unblock app Watchmen Rule Test",
        exact: true,
      })
      .click();
    await page
      .getByRole("button", {
        name: "Block app Watchmen Rule Test",
        exact: true,
      })
      .waitFor();
    const overlapping = await page.evaluate(() =>
      window.watchmen.firewallStatus(),
    );
    assert.equal(
      overlapping.value.rules.find((r) => r.kind === "app").enabled,
      false,
    );
    assert.equal(
      overlapping.value.rules.find((r) => r.kind === "connection").enabled,
      true,
    );
    await page
      .getByRole("button", {
        name: "Allow only Watchmen Rule Test",
        exact: true,
      })
      .click();
    const only = page.getByRole("dialog", {
      name: "Allow network access to only this app",
      exact: true,
    });
    await only.waitFor();
    assert.equal(
      await only
        .getByRole("button", { name: "Enable only-app mode", exact: true })
        .isEnabled(),
      false,
    );
    await only.getByRole("checkbox").check();
    await page.screenshot({ path: "test-results/only-app-review-dark.png" });
    await only
      .getByRole("button", { name: "Enable only-app mode", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Turn off app isolation", exact: true })
      .waitFor();
    await page
      .getByRole("button", { name: "Turn off app isolation", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Turn off app isolation", exact: true })
      .waitFor({ state: "hidden" });
    await page
      .getByRole("button", { name: "Network rules", exact: true })
      .click();
    await page.getByRole("button", { name: "Europe", exact: true }).click();
    await page
      .getByRole("button", { name: "Review region block", exact: true })
      .click();
    await page
      .getByRole("dialog", { name: "Block selected regions", exact: true })
      .waitFor();
    const europe = await page.getByRole("dialog").innerText();
    assert.ok(europe.includes("Germany") && europe.includes("France"));
    await page
      .getByRole("dialog")
      .getByRole("button", { name: "Cancel", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Clear selection", exact: true })
      .click();
    await page
      .getByRole("textbox", { name: "Find countries", exact: true })
      .fill("Canada");
    await page
      .getByRole("checkbox", { name: "Canada CA", exact: true })
      .check();
    await page
      .getByRole("button", { name: "Review region block", exact: true })
      .click();
    await page.getByRole("button", { name: "Block now", exact: true }).click();
    const rules = page.getByRole("table", {
      name: "Saved network rules",
      exact: true,
    });
    await rules.getByText("Canada", { exact: true }).waitFor();
    assert.ok(await rules.getByText("2026-10", { exact: true }).isVisible());
    await page
      .getByRole("textbox", { name: "Find countries", exact: true })
      .fill("");
    await page.screenshot({
      path: "test-results/network-rules-dark.png",
      fullPage: true,
    });
    // Exercise a long-running task through production IPC without touching real Windows policy.
    await page
      .getByRole("button", { name: "Allow Canada + US only", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Review country-only mode", exact: true })
      .click();
    const countryOnly = page.getByRole("dialog", {
      name: "Allow only selected countries / regions",
      exact: true,
    });
    await countryOnly.waitFor();
    assert.ok((await countryOnly.innerText()).includes("United States"));
    assert.ok(
      (await countryOnly.innerText()).toLowerCase().includes("unknown public locations"),
    );
    assert.equal(
      await countryOnly
        .getByRole("button", { name: "Enable country-only mode", exact: true })
        .isEnabled(),
      false,
    );
    await countryOnly.getByRole("checkbox").check();
    await application.evaluate(() => {
      global.__holdRuleTask = true;
    });
    await countryOnly
      .getByRole("button", { name: "Enable country-only mode", exact: true })
      .click();
    await countryOnly.getByRole("progressbar").waitFor();
    await countryOnly
      .getByRole("button", { name: "Minimize task", exact: true })
      .click();
    await countryOnly.waitFor({ state: "hidden" });
    const task = page.getByRole("complementary", {
      name: "Network rule task",
      exact: true,
    });
    await task.waitFor();
    assert.equal(
      await task.getByRole("progressbar").getAttribute("value"),
      "500",
    );
    await page
      .getByRole("navigation")
      .getByRole("button", { name: "Applications", exact: true })
      .click();
    await page
      .getByRole("row", {
        name: "Connections for Watchmen Rule Test",
        exact: true,
      })
      .waitFor();
    await page.screenshot({ path: "test-results/background-rule-task.png" });
    await task.getByRole("button", { name: "Show task", exact: true }).click();
    await countryOnly.waitFor();
    await countryOnly
      .getByRole("button", { name: "Minimize task", exact: true })
      .click();
    await task
      .getByRole("button", { name: "Cancel task", exact: true })
      .click();
    await page.waitForFunction(async () => {
      const r = await window.watchmen.firewallStatus();
      return r.ok && !r.value.busy && r.value.job?.status === "cancelled";
    });
    await task.getByRole("button", { name: "Show task", exact: true }).click();
    await application.evaluate(() => {
      global.__holdRuleTask = true;
    });
    await countryOnly
      .getByRole("button", { name: "Enable country-only mode", exact: true })
      .click();
    await countryOnly.getByRole("progressbar").waitFor();
    await countryOnly
      .getByRole("button", { name: "Minimize task", exact: true })
      .click();
    await application.evaluate(() => {
      global.__holdRuleTask = false;
      global.__finishRuleTask();
    });
    await page
      .getByRole("button", { name: "Turn off country-only mode", exact: true })
      .waitFor();
    await page.screenshot({ path: "test-results/country-only-active.png" });
    await page
      .getByRole("navigation")
      .getByRole("button", { name: "Network rules", exact: true })
      .click();
    await page.setViewportSize({ width: 1000, height: 760 });
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth > innerWidth,
      ),
      false,
    );
    await application.close();
    application = await launch();
    await installMock(true);
    await page
      .getByRole("button", { name: "Network rules", exact: true })
      .click();
    await page
      .getByRole("table", { name: "Saved network rules", exact: true })
      .getByText("Canada", { exact: true })
      .waitFor();
    const restored = await page.evaluate(() =>
      window.watchmen.firewallStatus(),
    );
    assert.equal(
      restored.value.rules.find((r) => r.kind === "region").enabled,
      true,
    );
    assert.equal(
      restored.value.rules.find((r) => r.kind === "app").enabled,
      false,
    );
    assert.ok(
      (
        await page.evaluate(() => window.watchmen.firewallStatus())
      ).value.rules.some((r) => r.kind === "onlyRegion" && r.enabled),
    );
    await page
      .getByRole("button", { name: "Unblock all Watchmen rules", exact: true })
      .click();
    await page
      .getByRole("status")
      .filter({ hasText: "All Watchmen restrictions are off." })
      .waitFor();
    const unblocked = await page.evaluate(() =>
      window.watchmen.firewallStatus(),
    );
    assert.ok(unblocked.value.rules.every((r) => !r.enabled));
    assert.deepEqual(errors, []);
    const result = {
      passed: true,
      packaged,
      transport: "Simulated Windows transport; production manager and UI",
      checks: [
        "administrator gating without mutation",
        "executable block from main table",
        "remote endpoint block from nested table",
        "independent overlapping rules",
        "direct table unblock",
        "only-app review acknowledgement",
        "only-app mode banner and restore",
        "continent and country selection",
        "dated region rule",
        "saved rules restored after restart",
        "unblock all",
        "minimum window width",
        "country-only Canada and US review, acknowledgement and persistence",
        "real progress display with minimize, navigation, restore and cancellation",
        "no renderer errors",
      ],
    };
    await fs.writeFile(
      "test-results/rules-smoke" + (packaged ? "-packaged" : "") + ".json",
      JSON.stringify(result, null, 2),
    );
    console.log(JSON.stringify(result, null, 2));
  } finally {
    await application.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
