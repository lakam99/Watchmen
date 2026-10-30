const { _electron: electron } = require("playwright"),
  fs = require("node:fs/promises"),
  path = require("node:path"),
  assert = require("node:assert/strict");
const delay = (ms) => new Promise((r) => setTimeout(r, ms));
(async () => {
  await fs.mkdir("test-results", { recursive: true });
  const workspace = await fs.mkdtemp(
      path.join(require("node:os").tmpdir(), "watchmen-tray-"),
    ),
    packaged = process.argv.includes("--packaged");
  await fs.mkdir(path.join(workspace, ".watchmen"));
  await fs.writeFile(
    path.join(workspace, ".watchmen/update-settings.json"),
    JSON.stringify({ autoCheck: false, autoDownload: false }),
  );
  const env = { ...process.env, WATCHMEN_WORKSPACE_DIR: workspace };
  delete env.ELECTRON_RUN_AS_NODE;
  const application = await electron.launch({
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
  let quit = false;
  try {
    const page = await application.firstWindow(),
      errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.waitForFunction(async () => {
      const s = await window.watchmen.getStatus();
      return !!s.timestamp && !s.agentError && s.profileStatus.available;
    });
    const initial = await page.evaluate(async () => ({
      snapshot: await window.watchmen.getStatus(),
      profile: await window.watchmen.trafficProfile({ range: "all" }),
    }));
    assert.equal(initial.profile.ok, true);
    const before = await application.evaluate(({ app, BrowserWindow }) => {
      const require = process
          .getBuiltinModule("module")
          .createRequire(app.getAppPath() + "/electron/main.cjs"),
        { Background } = require("./background.cjs"),
        original = Background.prototype.hide;
      Background.prototype.hide = function (...args) {
        global.__background = this;
        return original.apply(this, args);
      };
      const win = BrowserWindow.getAllWindows()[0];
      global.__backgroundWebContents = win.webContents.id;
      const output = require("node:child_process")
        .execFileSync(
          "powershell.exe",
          [
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            `Get-CimInstance Win32_Process -Filter "ParentProcessId = ${process.pid} AND Name = 'Watchmen.Agent.exe'" | Select-Object -ExpandProperty ProcessId | ConvertTo-Json -Compress`,
          ],
          { windowsHide: true, encoding: "utf8" },
        )
        .trim();
      win.close();
      const bg = global.__background;
      return {
        hidden: !win.isVisible(),
        destroyed: win.isDestroyed(),
        trayAvailable: bg.available(),
        trayBounds: bg.tray.getBounds(),
        backgroundThrottling: win.webContents.backgroundThrottling,
        collectorPids: output ? [JSON.parse(output)].flat() : [],
      };
    });
    assert.equal(before.hidden, true);
    assert.equal(before.destroyed, false);
    assert.equal(before.trayAvailable, true);
    assert.ok(before.trayBounds.width > 0);
    assert.equal(before.backgroundThrottling, false);
    assert.ok(before.collectorPids.length > 0);
    await page.waitForFunction(async (timestamp) => {
      const s = await window.watchmen.getStatus();
      return (
        Date.parse(s.timestamp) > Date.parse(timestamp) + 5000 && !s.agentError
      );
    }, initial.snapshot.timestamp);
    const hidden = await page.evaluate(async () => ({
      snapshot: await window.watchmen.getStatus(),
      profile: await window.watchmen.trafficProfile({ range: "all" }),
    }));
    assert.equal(hidden.profile.ok, true);
    assert.ok(
      hidden.profile.value.totals.observations >
        initial.profile.value.totals.observations,
      "Database profiling must continue while hidden",
    );
    const restored = await application.evaluate(({ BrowserWindow }) => {
      const bg = global.__background;
      bg.menu.getMenuItemById("show-watchmen").click();
      const win = BrowserWindow.getAllWindows()[0];
      return {
        visible: win.isVisible(),
        sameWindow: win.webContents.id === global.__backgroundWebContents,
        quitting: bg.quitting,
      };
    });
    assert.equal(restored.visible, true);
    assert.equal(restored.sameWindow, true);
    assert.equal(restored.quitting, false);
    await page.screenshot({
      path: "test-results/background-restored.png",
      fullPage: true,
    });
    const clicked = await application.evaluate(() => {
      const bg = global.__background;
      bg.tray.emit("click");
      bg.menu.getMenuItemById("hide-watchmen").click();
      return !bg.win.isVisible();
    });
    assert.equal(clicked, true);
    // Use the actual registered Quit menu handler; no installer/UAC/firewall mutation.
    const closed = new Promise((resolve) => application.once("close", resolve));
    const updateQuit = process.argv.includes("--update-quit");
    await application.evaluate(({ autoUpdater }, updateQuit) => {
      if (updateQuit) {
        autoUpdater.emit("before-quit-for-update");
        global.__background.win.close();
      } else global.__background.menu.getMenuItemById("quit-watchmen").click();
      return true;
    }, updateQuit);
    await Promise.race([
      closed,
      delay(12000).then(() => {
        throw new Error("Tray Quit did not stop Watchmen");
      }),
    ]);
    quit = true;
    for (const pid of before.collectorPids) {
      let alive = true;
      for (let i = 0; i < 20; i++) {
        try {
          process.kill(pid, 0);
        } catch {
          alive = false;
          break;
        }
        await delay(100);
      }
      assert.equal(alive, false, "Collector must exit with Watchmen");
    }
    assert.deepEqual(errors, []);
    const report = {
      passed: true,
      packaged,
      version: require("../package.json").version,
      updateQuit,
      checks: [
        "real Windows tray icon and menu",
        "close hides without destroying window",
        "same window restored by registered tray menu",
        "icon click callback",
        "collector snapshots advance while hidden",
        "SQLite observations grow while hidden",
        "unthrottled hidden renderer",
        updateQuit
          ? "native update-quit event bypasses close-to-tray and exits collector"
          : "tray Quit exits app and native collector",
      ],
      trayBounds: before.trayBounds,
      initialObservations: initial.profile.value.totals.observations,
      hiddenObservations: hidden.profile.value.totals.observations,
      installerExecuted: false,
      errors,
    };
    await fs.writeFile(
      `test-results/background-smoke${updateQuit ? "-update-quit" : ""}${packaged ? "-packaged" : ""}.json`,
      JSON.stringify(report, null, 2),
    );
    console.log(JSON.stringify(report, null, 2));
  } finally {
    if (!quit) await application.close();
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
