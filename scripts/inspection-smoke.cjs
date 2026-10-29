const { _electron: electron } = require("playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const { TrafficStore } = require("../electron/traffic-store.cjs");
const { frame, pcap } = require("../tests/packet-fixtures.cjs");
(async () => {
  await fs.mkdir("test-results", { recursive: true });
  const seedIndex = process.argv.indexOf("--seed-profile");
  const workspace =
    seedIndex >= 0
      ? process.argv[seedIndex + 1]
      : await fs.mkdtemp(
          path.join(process.cwd(), "test-results", "inspection-workspace-"),
        );
  if (seedIndex >= 0) {
    let time = Date.now() - 600000;
    const store = new TrafficStore(
      path.join(workspace, ".watchmen", "traffic.sqlite"),
      { clock: () => time, sessionId: "fixture" },
    );
    const base = {
      id: "fixture-base",
      app: "Watchmen Test Fixture",
      processPath: "C:/test-fixture.exe",
      pid: 1,
      protocol: "TCP",
      remoteAddress: "8.8.8.8",
      remotePort: 443,
      localAddress: "192.168.1.2",
      localPort: 50123,
      active: true,
      state: "Established",
      received: 0,
      sent: 0,
      firstSeen: new Date(time).toISOString(),
    };
    const ingest = (rows) =>
      store.ingest({
        timestamp: new Date(time).toISOString(),
        startedAt: base.firstSeen,
        tracing: false,
        eventsLost: 0,
        flows: rows,
      });
    ingest([base]);
    for (let i = 0; i < 61; i++) {
      time += 2000;
      ingest([base]);
    }
    time += 2000;
    ingest([
      {
        ...base,
        id: "new-fixture",
        remoteAddress: "203.0.113.10",
        remotePort: 8443,
        firstSeen: new Date(time).toISOString(),
      },
    ]);
    store.close();
    return;
  }
  // Release every SQLite/WAL handle before Electron opens this fixture under
  // its own SQLite runtime; cached prepared statements can outlive close().
  require("node:child_process").execFileSync(
    process.execPath,
    [__filename, "--seed-profile", workspace],
    { stdio: "pipe", timeout: 30000 },
  );
  const capture = path.join(workspace, "readable-test.pcap");
  await fs.writeFile(
    capture,
    pcap([
      frame(
        "GET /watchmen?token=synthetic-private HTTP/1.1\r\nAuthorization: Bearer synthetic-private\r\n\r\nHuman readable test body",
        { destination: "203.0.113.10", destinationPort: 8443 },
      ),
      frame(Buffer.from([23, 3, 3, 0, 5, 1, 2, 3, 4, 5]), {
        destination: "203.0.113.10",
        destinationPort: 443,
      }),
    ]),
  );
  const env = { ...process.env, WATCHMEN_WORKSPACE_DIR: workspace };
  delete env.ELECTRON_RUN_AS_NODE;
  const packaged = process.argv.includes("--packaged");
  const launch = async () => {
    const instance = await electron.launch({
      timeout: 60000,
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
    });
    await instance.evaluate(({ BrowserWindow }) =>
      BrowserWindow.getAllWindows().forEach((window) => window.showInactive()),
    );
    return instance;
  };
  let app = await launch();
  const errors = [];
  try {
    let page = await app.firstWindow();
    page.on("pageerror", (e) => errors.push(e.message));
    await page.waitForFunction(() => document.querySelector("tbody tr"));
    const saved = await page.evaluate(() =>
      window.watchmen.saveAI({
        provider: "openrouter",
        baseUrl: "https://openrouter.ai/api/v1",
        model: "mock-model",
        token: "synthetic-integration-token",
      }),
    );
    assert.ok(saved.ok);
    await page.reload();
    await page.waitForFunction(() => document.querySelector("tbody tr"));
    await app.evaluate(({ net }) => {
      global.__changeRequest = null;
      net.fetch = async (url, options) => {
        global.__changeRequest = { url, body: options.body };
        return new Response(
          JSON.stringify({
            choices: [
              {
                message: {
                  content:
                    "What changed: the app added TCP/8443 after its saved TCP/443 baseline. This metadata alone does not establish a threat.",
                },
              },
            ],
          }),
        );
      };
    });
    await page.getByRole("button", { name: "Changes", exact: true }).click();
    await page
      .getByRole("row", {
        name: "Review New service for Watchmen Test Fixture",
        exact: true,
      })
      .click();
    await page
      .getByRole("button", { name: "Explain this change", exact: true })
      .click();
    await page
      .getByText("Review exact metadata to share", { exact: true })
      .waitFor();
    await page
      .getByRole("button", { name: "Generate explanation", exact: true })
      .click();
    await page
      .getByText("What changed: the app added TCP/8443", { exact: false })
      .waitFor();
    const request = await app.evaluate(() => global.__changeRequest);
    assert.equal(request.url, "https://openrouter.ai/api/v1/chat/completions");
    assert.ok(!request.body.includes("203.0.113.10"));
    assert.ok(!request.body.includes("Human readable test body"));
    await page.getByRole("button", { name: "Settings & privacy" }).click();
    await page.getByRole("button", { name: "Dark", exact: true }).click();
    await page.getByRole("button", { name: "Back to my network" }).click();
    await page.setViewportSize({ width: 1440, height: 1050 });
    await app.evaluate(({ BrowserWindow }) =>
      BrowserWindow.getAllWindows()[0].showInactive(),
    );
    await page.screenshot({ path: "test-results/changes-insight-dark.png" });
    await app.evaluate(({ BrowserWindow }) =>
      BrowserWindow.getAllWindows()[0].showInactive(),
    );
    await app.evaluate(({ dialog }, filename) => {
      dialog.showOpenDialog = async () => ({
        canceled: false,
        filePaths: [filename],
      });
    }, capture);
    await page
      .getByRole("button", { name: "Inspect packets", exact: true })
      .click();
    await page.getByRole("button", { name: "Open PCAP", exact: true }).click();
    await page.getByRole("row", { name: "Read packet 1", exact: true }).click();
    await page.getByRole("region", { name: "Packet contents" }).waitFor();
    assert.ok(
      await page
        .getByText("Human readable test body", { exact: false })
        .isVisible(),
    );
    assert.equal(
      await page
        .locator("body")
        .innerText()
        .then((text) => text.includes("synthetic-private")),
      false,
    );
    await app.evaluate(({ BrowserWindow }) =>
      BrowserWindow.getAllWindows()[0].showInactive(),
    );
    await page.screenshot({
      path: "test-results/readable-packets-dark.png",
      fullPage: true,
    });
    await app.evaluate(({ BrowserWindow }) =>
      BrowserWindow.getAllWindows()[0].showInactive(),
    );
    await page.getByRole("row", { name: "Read packet 2", exact: true }).click();
    await page
      .getByText("Encrypted or secure-protocol data.", { exact: false })
      .waitFor();
    await page.getByRole("button", { name: "Changes", exact: true }).click();
    await page
      .getByRole("row", {
        name: "Review New service for Watchmen Test Fixture",
        exact: true,
      })
      .click();
    await page.getByRole("button", { name: "Dismiss", exact: true }).click();
    await page
      .getByRole("combobox", { name: "Change status" })
      .selectOption("dismissed");
    await page
      .getByRole("row", {
        name: "Review New service for Watchmen Test Fixture",
        exact: true,
      })
      .waitFor();
    await app.close();
    app = await launch();
    page = await app.firstWindow();
    page.on("pageerror", (e) => errors.push(e.message));
    await page.waitForFunction(() => document.querySelector("tbody tr"));
    await page.getByRole("button", { name: "Changes", exact: true }).click();
    await page
      .getByRole("combobox", { name: "Change status" })
      .selectOption("dismissed");
    await page
      .getByRole("row", {
        name: "Review New service for Watchmen Test Fixture",
        exact: true,
      })
      .click();
    await page
      .getByText("What changed: the app added TCP/8443", { exact: false })
      .waitFor();
    const packetState = await page.evaluate(() =>
      window.watchmen.packetsStatus(),
    );
    assert.equal(packetState.value.totalRecords, 0);
    await page.setViewportSize({ width: 1000, height: 760 });
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth > innerWidth,
      ),
      false,
    );
    assert.deepEqual(errors, []);
    const result = {
      passed: true,
      packaged,
      checks: [
        "profile-based new destination and service alerts",
        "frozen before/after evidence",
        "OpenRouter explanation with mocked provider",
        "destination IP omitted by default",
        "packet contents absent from AI request",
        "PCAP import without elevation",
        "human-readable HTTP payload",
        "credential header and token redaction",
        "TLS remains encrypted",
        "dismissal persists across restart",
        "saved explanation survives restart",
        "packet contents not persisted across restart",
        "minimum width",
        "no renderer exceptions",
      ],
    };
    await fs.writeFile(
      "test-results/inspection-smoke" + (packaged ? "-packaged" : "") + ".json",
      JSON.stringify(result, null, 2),
    );
    console.log(JSON.stringify(result, null, 2));
  } finally {
    await app.close();
    await fs
      .rm(path.join(workspace, ".watchmen", "ai-token.bin"), { force: true })
      .catch(() => {});
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

