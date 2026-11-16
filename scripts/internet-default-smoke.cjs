const { _electron: electron } = require("playwright");
const fs = require("node:fs/promises"),
  path = require("node:path"),
  os = require("node:os"),
  assert = require("node:assert/strict");
(async () => {
  const workspace = await fs.mkdtemp(
    path.join(os.tmpdir(), "watchmen-internet-"),
  );
  await fs.mkdir(path.join(workspace, ".watchmen"));
  await fs.writeFile(
    path.join(workspace, ".watchmen/update-settings.json"),
    JSON.stringify({ autoCheck: false, autoDownload: false }),
  );
  const env = { ...process.env, WATCHMEN_WORKSPACE_DIR: workspace };
  delete env.ELECTRON_RUN_AS_NODE;
  const app = await electron.launch({
    executablePath: path.resolve(
      "release",
      require("../package.json").version,
      "Watchmen-win32-x64/Watchmen.exe",
    ),
    args: ["--user-data-dir=" + path.join(workspace, "chromium")],
    env,
    timeout: 60000,
  });
  const errors = [];
  try {
    const page = await app.firstWindow();
    page.on("pageerror", (e) => errors.push(e.message));
    await page.waitForFunction(() => window.watchmen);
    await app.evaluate(({ BrowserWindow, ipcMain }) => {
      const win = BrowserWindow.getAllWindows()[0],
        send = win.webContents.send.bind(win.webContents);
      const base = {
        pid: 9001,
        processPath: "",
        protocol: "TCP",
        localAddress: "192.168.1.2",
        localPort: 55000,
        remotePort: 443,
        active: true,
        state: "Established",
        received: 0,
        sent: 0,
        rxRate: 0,
        txRate: 0,
      };
      const flows = [
        {
          ...base,
          id: "internet",
          app: "Internet Fixture",
          remoteAddress: "8.8.8.8",
        },
        {
          ...base,
          id: "lan",
          app: "LAN Fixture",
          remoteAddress: "192.168.1.3",
        },
        {
          ...base,
          id: "listener",
          app: "Listener Fixture",
          remoteAddress: "*",
          remotePort: 0,
          state: "Listen",
        },
      ];
      win.webContents.send = (channel, ...args) =>
        send(
          channel,
          ...(channel === "snapshot" ? [{ ...args[0], flows }] : args),
        );
      win.webContents.send("snapshot", {
        timestamp: new Date().toISOString(),
        adapters: [],
        locations: {},
        flows,
        rxRate: 0,
        txRate: 0,
      });
    });
    const scope = page.getByRole("combobox", {
      name: "Network scope",
      exact: true,
    });
    await scope.waitFor();
    assert.equal(await scope.inputValue(), "internet");
    const rows = page.locator("tbody");
    await page.getByText("Internet Fixture", { exact: true }).first().waitFor();
    assert.ok(!(await rows.innerText()).includes("Listener Fixture"));
    assert.ok(!(await rows.innerText()).includes("LAN Fixture"));
    await scope.selectOption("listener");
    await page.getByText("Listener Fixture", { exact: true }).first().waitFor();
    await scope.selectOption("local");
    await page.getByText("LAN Fixture", { exact: true }).first().waitFor();
    await scope.selectOption("all");
    await page.getByText("Internet Fixture", { exact: true }).first().waitFor();
    assert.match(await rows.innerText(), /Listener Fixture/);
    assert.match(await rows.innerText(), /LAN Fixture/);
    await page
      .getByRole("textbox", { name: "Search traffic" })
      .fill("absent-fixture");
    await page
      .getByRole("button", { name: "Reset filters", exact: true })
      .click();
    assert.equal(await scope.inputValue(), "internet");
    assert.equal(
      await page
        .getByRole("combobox", { name: "Connection activity", exact: true })
        .inputValue(),
      "active",
    );
    await page.screenshot({
      path: "test-results/internet-default.png",
      fullPage: true,
    });
    await scope.selectOption("all");
    await page.waitForTimeout(600);
    assert.equal(
      (await page.evaluate(() => window.watchmen.viewSettings())).value.filter,
      "all",
    );
    await page.reload();
    await page
      .getByRole("combobox", { name: "Network scope", exact: true })
      .waitFor();
    await page.waitForFunction(
      () =>
        document.querySelector('[aria-label="Network scope"]').value === "all",
    );
    assert.deepEqual(errors, []);
    const result = {
      passed: true,
      packaged: true,
      checks: [
        "Internet default hides LAN and listeners",
        "explicit LAN/listener/all access",
        "reset restores active Internet",
        "explicit All choice persists across renderer reload",
        "no renderer exceptions",
      ],
    };
    await fs.writeFile(
      "test-results/internet-default-smoke.json",
      JSON.stringify(result, null, 2),
    );
    console.log(result);
  } finally {
    await app.close();
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
