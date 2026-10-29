const { _electron: electron } = require("playwright"),
  fs = require("node:fs/promises"),
  path = require("node:path"),
  assert = require("node:assert/strict");
(async () => {
  await fs.mkdir("test-results", { recursive: true });
  const workspace = await fs.mkdtemp(
    path.join(require("node:os").tmpdir(), "watchmen-updates-ui-"),
  );
  await fs.mkdir(path.join(workspace, ".watchmen"));
  await fs.writeFile(
    path.join(workspace, ".watchmen/update-settings.json"),
    JSON.stringify({ autoCheck: false, autoDownload: false }),
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
  let application = await launch(),
    page;
  const errors = [];
  async function mock() {
    page = await application.firstWindow({ timeout: 60000 });
    page.on("pageerror", (e) => errors.push(e.message));
    application
      .process()
      .stderr.on("data", (data) => process.stderr.write(data));
    page.on("console", (message) => {
      if (message.type() === "error")
        console.error("Renderer:", message.text());
    });
    await page.waitForFunction(() => window.watchmen);
    await application.evaluate(
      async ({ app, ipcMain, BrowserWindow }, { workspace }) => {
        const require = process
            .getBuiltinModule("module")
            .createRequire(app.getAppPath() + "/electron/main.cjs"),
          { EventEmitter } = require("node:events"),
          { Updates } = require(app.getAppPath() + "/electron/updates.cjs");
        class Adapter extends EventEmitter {
          async checkForUpdates() {
            this.emit("checking-for-update");
            await new Promise((r) => setTimeout(r, 40));
            this.emit("update-available", { version: "0.8.0" });
            return {};
          }
          async downloadUpdate() {
            this.emit("download-progress", {
              percent: 50,
              transferred: 52428800,
              total: 104857600,
              bytesPerSecond: 1048576,
            });
            await new Promise(
              (resolve) => (global.__finishUpdateDownload = resolve),
            );
            this.emit("update-downloaded", { version: "0.8.0" });
          }
          quitAndInstall(...args) {
            global.__updateInstallArgs = args;
          }
        }
        const adapter = new Adapter(),
          manager = new Updates(workspace + "/.watchmen", {
            adapter,
            version: app.getVersion(),
            supported: true,
            blocked: () =>
              global.__updateRuleBusy
                ? "Wait for the current network-rule task to finish before restarting."
                : null,
          });
        await manager.init();
        global.__updates = manager;
        global.__updateAdapter = adapter;
        const handlers = {
          "updates-status": () => manager.status(),
          "updates-check": () => manager.check(),
          "updates-download": () => manager.download(),
          "updates-configure": (input) => manager.configure(input),
          "updates-install": () => manager.install(),
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
      },
      { workspace },
    );
  }
  try {
    await mock();
    await page
      .getByRole("button", { name: "Settings & privacy", exact: true })
      .click();
    await page.getByRole("button", { name: "Dark", exact: true }).click();
    let section = page.getByRole("region", {
      name: "App updates",
      exact: true,
    });
    await section.waitFor();
    await section
      .getByRole("button", { name: "Check for updates", exact: true })
      .click();
    await section
      .getByRole("button", { name: "Download update", exact: true })
      .click();
    await section
      .getByRole("progressbar", {
        name: "Update download progress",
        exact: true,
      })
      .waitFor();
    assert.equal(
      await section.getByRole("progressbar").getAttribute("value"),
      "50",
    );
    await section.screenshot({ path: "test-results/update-download-dark.png" });
    await page
      .getByRole("button", { name: "Back to my network", exact: true })
      .click();
    await page.getByRole("button", { name: "Pause view", exact: true }).click();
    await page.getByRole("button", { name: "Resume", exact: true }).click();
    await application.evaluate(() => {
      global.__updateRuleBusy = true;
      global.__finishUpdateDownload();
    });
    await page
      .getByRole("button", { name: "Install & restart", exact: true })
      .waitFor();
    assert.equal(
      await page
        .getByRole("button", { name: "Install & restart", exact: true })
        .isEnabled(),
      false,
    );
    await application.evaluate(() => (global.__updateRuleBusy = false));
    await page
      .getByRole("button", { name: "Install & restart", exact: true })
      .click();
    assert.deepEqual(
      await application.evaluate(() => global.__updateInstallArgs),
      [false, true],
    );
    await application.evaluate(() =>
      global.__updateAdapter.emit(
        "error",
        new Error("sha512 mismatch secret fixture"),
      ),
    );
    await page
      .getByRole("button", { name: "Settings & privacy", exact: true })
      .click();
    section = page.getByRole("region", { name: "App updates", exact: true });
    await section
      .getByRole("alert")
      .filter({ hasText: "Update verification failed" })
      .waitFor();
    assert.equal((await section.innerText()).includes("secret fixture"), false);
    await section
      .getByRole("checkbox", {
        name: "Download available updates in the background",
        exact: true,
      })
      .check();
    await page.waitForFunction(async () => {
      const r = await window.watchmen.updatesStatus();
      return r.value.autoDownload;
    });
    await application.close();
    application = await launch();
    await mock();
    await page
      .getByRole("button", { name: "Settings & privacy", exact: true })
      .click();
    section = page.getByRole("region", { name: "App updates", exact: true });
    await section.waitFor();
    assert.equal(
      await section
        .getByRole("checkbox", {
          name: "Download available updates in the background",
          exact: true,
        })
        .isChecked(),
      true,
    );
    // Exercise the actual Electron updater over a test-only local feed. The corrupt file must never become installable.
    const sdk = await application.evaluate(
      async ({ app }, { workspace }) => {
        const require = process
            .getBuiltinModule("module")
            .createRequire(app.getAppPath() + "/electron/main.cjs"),
          fs = require("node:fs/promises"),
          path = require("node:path"),
          http = require("node:http"),
          crypto = require("node:crypto"),
          { NsisUpdater } = require("electron-updater"),
          {
            ElectronHttpExecutor,
          } = require("electron-updater/out/electronHttpExecutor"),
          { Updates } = require(app.getAppPath() + "/electron/updates.cjs");
        const payload = Buffer.from("corrupt update fixture"),
          badHash = crypto
            .createHash("sha512")
            .update("different expected content")
            .digest("base64");
        const metadata = {
          version: "0.8.0",
          files: [{ url: "update.exe", sha512: badHash, size: payload.length }],
          path: "update.exe",
          sha512: badHash,
          releaseDate: new Date().toISOString(),
        };
        const server = http.createServer((req, res) => {
          if (req.url.startsWith("/latest.yml")) {
            res.setHeader("Content-Type", "text/yaml");
            res.end(JSON.stringify(metadata));
          } else if (req.url.startsWith("/update.exe")) {
            res.setHeader("Content-Type", "application/octet-stream");
            res.setHeader("Content-Length", payload.length);
            res.end(payload);
          } else {
            res.writeHead(404);
            res.end();
          }
        });
        await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
        const userData = path.join(workspace, "sdk-userData"),
          cache = path.join(workspace, "sdk-cache"),
          config = path.join(workspace, "sdk-app-update.yml");
        await fs.mkdir(userData, { recursive: true });
        await fs.writeFile(config, "updaterCacheDirName: fixture-updater\n");
        const adapter = {
          version: "0.7.0",
          name: "WatchmenUpdateFixture",
          isPackaged: true,
          whenReady: () => app.whenReady(),
          appUpdateConfigPath: config,
          userDataPath: userData,
          baseCachePath: cache,
          quit: () => {
            throw new Error("Fixture must never install");
          },
          onQuit: () => {},
        };
        const updater = new NsisUpdater(null, adapter);
        updater.httpExecutor = new ElectronHttpExecutor(() => {});
        updater.setFeedURL({
          provider: "generic",
          url: "http://127.0.0.1:" + server.address().port + "/",
        });
        const manager = new Updates(path.join(workspace, "sdk-settings"), {
          adapter: updater,
          version: "0.7.0",
          supported: true,
        });
        try {
          await manager.configure({ autoCheck: false, autoDownload: false });
          await manager.check();
          const available = manager.status().phase;
          await manager.download();
          return {
            available,
            final: manager.status().phase,
            error: manager.status().error,
            ready: manager.status().phase === "ready",
          };
        } finally {
          manager.dispose();
          await new Promise((resolve) => server.close(resolve));
        }
      },
      { workspace },
    );
    assert.equal(sdk.available, "available");
    assert.equal(sdk.final, "error");
    assert.equal(sdk.ready, false);
    assert.match(sdk.error, /verification failed/i);
    assert.deepEqual(errors, []);
    const result = {
      passed: true,
      packaged,
      checks: [
        "available release and download progress",
        "monitor pause/resume during download",
        "restart blocked during rule work",
        "explicit installer handoff with simulated installer",
        "persistent update preferences",
        "real Electron updater rejects corrupted download",
        "no renderer errors",
      ],
      realSdk: sdk,
    };
    await fs.writeFile(
      "test-results/updates-smoke" + (packaged ? "-packaged" : "") + ".json",
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
