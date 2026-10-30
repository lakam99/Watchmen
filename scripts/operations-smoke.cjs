const { _electron: electron } = require("playwright"),
  fs = require("node:fs/promises"),
  path = require("node:path"),
  assert = require("node:assert/strict");
(async () => {
  const workspace = await fs.mkdtemp(
      path.join(require("node:os").tmpdir(), "watchmen-operations-"),
    ),
    provider = process.argv.includes("--openai") ? "openai" : "openrouter",
    packaged = process.argv.includes("--packaged");
  await fs.mkdir(path.join(workspace, ".watchmen"));
  await fs.writeFile(
    path.join(workspace, ".watchmen/update-settings.json"),
    JSON.stringify({ autoCheck: false, autoDownload: false }),
  );
  const env = { ...process.env, WATCHMEN_WORKSPACE_DIR: workspace };
  delete env.ELECTRON_RUN_AS_NODE;
  const app = await electron.launch({
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
  const page = await app.firstWindow(),
    errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  try {
    await page
      .getByRole("navigation")
      .getByRole("button", { name: "AI console", exact: true })
      .click();
    await app.evaluate(async ({ app, ipcMain, BrowserWindow }, provider) => {
      const require = process
          .getBuiltinModule("module")
          .createRequire(app.getAppPath() + "/electron/main.cjs"),
        { Assistant } = require("./assistant.cjs"),
        { AppViewBridge } = require("./app-view-bridge.cjs"),
        { Firewall } = require("./firewall.cjs"),
        { SettingsStore } = require("./settings-store.cjs");
      const win = BrowserWindow.getAllWindows()[0],
        calls = [],
        snapshot = {
          timestamp: new Date().toISOString(),
          startedAt: new Date().toISOString(),
          tracing: true,
          rxRate: 0,
          txRate: 0,
          errors: [],
          agentError: null,
          locations: {},
          locationsEnabled: false,
          eventsLost: 0,
          evictedFlows: 0,
          admin: true,
          flows: [
            {
              id: "fixture",
              pid: 9001,
              app: "Relay Browser",
              processPath: "C:\\FixtureApps\\Relay.exe",
              protocol: "TCP",
              remoteAddress: "8.8.8.8",
              localAddress: "10.0.0.1",
              remotePort: 443,
              active: true,
            },
          ],
          adapters: [],
        };
      const originalSend = win.webContents.send.bind(win.webContents);
      win.webContents.send = (channel, ...args) =>
        originalSend(channel, ...(channel === "snapshot" ? [snapshot] : args));
      ipcMain.removeHandler("status");
      ipcMain.handle("status", () => snapshot);
      win.webContents.send("snapshot", snapshot);
      const firewall = new Firewall("unused-operations-fixture", {
        snapshot: () => snapshot,
        transport: async () => ({
          rules: [],
          profiles: [],
          isolationVerified: true,
        }),
      });
      const packet = {
        id: "1",
        timestamp: Date.now(),
        source: "10.0.0.1",
        destination: "8.8.8.8",
        protocol: "TCP",
        sourcePort: 50000,
        destinationPort: 80,
        direction: "out",
        app: "Relay Browser",
        summary: "LOCAL PAYLOAD MARKER",
        length: 80,
        capturedLength: 80,
        truncated: false,
        encrypted: false,
      };
      let active = false;
      const packets = {
        status: () => ({
          active,
          processing: false,
          packets: [packet],
          totalRecords: 1,
          displayLimit: 500,
        }),
        start: async (seconds) => {
          calls.push(["capture", seconds]);
          active = true;
        },
        stop: async () => {
          active = false;
          calls.push("stop");
        },
      };
      const bridge = new AppViewBridge((c) =>
        win.webContents.send("app-operation", c),
      );
      const manager = new Assistant({
        preferences: {
          credential: async () => ({
            provider,
            baseUrl:
              provider === "openai"
                ? "https://api.openai.com/v1"
                : "https://openrouter.ai/api/v1",
            model: "fixture/tools",
            token: "synthetic-no-paid-requests",
          }),
        },
        settings: {
          get: () => ({ shareIPs: false, webSearch: false, ipLookups: false }),
        },
        snapshot: () => snapshot,
        history: () => null,
        firewall,
        operations: {
          packets,
          snapshot,
          showView: (c, s) => bridge.request(c, s),
          importCapture: async () => {
            calls.push("import");
            return null;
          },
          exportSession: async () => {
            calls.push("export");
            return { canceled: true };
          },
        },
        changed: (state) => win.webContents.send("assistant-state", state),
        fetch: async (url, init) => {
          const body = JSON.parse(init.body);
          if (!JSON.stringify(body).includes("propose_app_action"))
            throw new Error("Missing operational functions");
          if (
            /LOCAL PAYLOAD MARKER|LOCAL DECODED BODY/.test(JSON.stringify(body))
          )
            throw new Error("Packet content leaked");
          const messages = body.messages || body.input,
            results = messages.filter(
              (m) => m.role === "tool" || m.type === "function_call_output",
            );
          const output = results.length
            ? {
                content: "Capture review prepared. Local approval is required.",
              }
            : {
                tool_calls: [
                  {
                    id: "call_capture",
                    type: "function",
                    function: {
                      name: "propose_app_action",
                      arguments: JSON.stringify({
                        task: "start_capture",
                        seconds: "5",
                      }),
                    },
                  },
                ],
              };
          return new Response(
            JSON.stringify(
              provider === "openai"
                ? {
                    status: "completed",
                    output: output.tool_calls
                      ? output.tool_calls.map((c) => ({
                          type: "function_call",
                          status: "completed",
                          id: "fc_capture",
                          call_id: c.id,
                          name: c.function.name,
                          arguments: c.function.arguments,
                        }))
                      : [
                          {
                            type: "message",
                            role: "assistant",
                            status: "completed",
                            content: [
                              { type: "output_text", text: output.content },
                            ],
                          },
                        ],
                  }
                : { choices: [{ message: { role: "assistant", ...output } }] },
            ),
          );
        },
      });
      const handlers = {
        "assistant-status": () => manager.status(),
        "assistant-send": (text) => manager.send(text),
        "assistant-approve": (id, ack) => manager.approve(id, ack),
        "assistant-reject": (id) => manager.reject(id),
        "app-operation-ack": (id, error) => bridge.acknowledge(id, error),
        "packets-status": () => packets.status(),
        "packets-detail": (id) => ({
          ...packet,
          headers: [{ name: "Transport", value: "TCP" }],
          payloadText: "LOCAL DECODED BODY",
          hexHeaders: "00 01",
        }),
      };
      for (const [name, handler] of Object.entries(handlers)) {
        ipcMain.removeHandler(name);
        ipcMain.handle(name, async (e, ...args) => {
          if (e.sender !== win.webContents) throw new Error("Untrusted sender");
          try {
            return { ok: true, value: await handler(...args) };
          } catch (e) {
            return { ok: false, error: e.message };
          }
        });
      }
      global.__operations = {
        manager,
        snapshot,
        calls,
        packets,
        settings: new SettingsStore(
          require("node:path").join(
            process.env.WATCHMEN_WORKSPACE_DIR,
            ".watchmen",
          ),
        ),
      };
      win.webContents.send("assistant-state", manager.status());
    }, provider);
    // Run the real provider loop, then approve through the production review UI.
    const response = await page.evaluate(() =>
      window.watchmen.assistantSend("Prepare a five-second packet capture"),
    );
    assert.equal(response.ok, true);
    const review = page.getByRole("region", {
      name: "AI action review",
      exact: true,
    });
    await review
      .getByRole("heading", { name: "Start local packet capture" })
      .waitFor();
    assert.deepEqual(await app.evaluate(() => global.__operations.calls), []);
    await page.screenshot({
      path: `test-results/operations-review-${provider}.png`,
      fullPage: true,
    });
    await review
      .getByRole("button", { name: "Approve task", exact: true })
      .click();
    await review
      .getByText("Local capture started.", { exact: false })
      .waitFor();
    assert.deepEqual(await app.evaluate(() => global.__operations.calls), [
      ["capture", 5],
    ]);
    // Tools use the real bridge, preload and React state handling; packet bodies remain local.
    const refs = await app.evaluate(async () => {
      const t = global.__operations.manager.tools;
      return t.execute("packet_headers", {}, { shareIPs: false });
    });
    assert.ok(!JSON.stringify(refs).includes("LOCAL PAYLOAD"));
    await app.evaluate(
      async (_, ref) =>
        global.__operations.manager.tools.execute(
          "show_view",
          { targetRef: ref },
          { shareIPs: false },
        ),
      refs.packets[0].packetRef,
    );
    await page.getByText("LOCAL DECODED BODY", { exact: true }).waitFor();
    await page.screenshot({
      path: `test-results/operations-local-packet-${provider}.png`,
      fullPage: true,
    });
    await app.evaluate(async () =>
      global.__operations.manager.tools.execute(
        "show_view",
        {
          page: "Applications",
          query: "Relay",
          group: "app",
          scope: "internet",
          activity: "all",
          display: "pause",
          window: "300",
        },
        { shareIPs: false },
      ),
    );
    await assert.equal(
      await page
        .getByRole("textbox", { name: "Search traffic", exact: true })
        .inputValue(),
      "Relay",
    );
    assert.equal(
      await page.getByRole("combobox", { name: "Network scope" }).inputValue(),
      "internet",
    );
    assert.equal(
      await page
        .getByRole("combobox", { name: "Connection activity" })
        .inputValue(),
      "all",
    );
    await app.evaluate(async () =>
      global.__operations.manager.tools.execute(
        "show_view",
        {
          page: "Traffic profile",
          query: "Relay",
          range: "30d",
          tab: "destinations",
          metric: "bytes",
        },
        { shareIPs: false },
      ),
    );
    await page
      .getByRole("table", { name: "Saved destination profiles" })
      .waitFor();
    await app.evaluate(async () =>
      global.__operations.manager.tools.execute(
        "show_view",
        { page: "Network rules", query: "Relay", ruleStatus: "inactive" },
        { shareIPs: false },
      ),
    );
    await page.getByRole("table", { name: "Saved network rules" }).waitFor();
    // A non-admin local task must still be approvable, and cancellation means no file was written.
    await app.evaluate(async () => {
      const m = global.__operations.manager;
      global.__operations.snapshot.admin = false;
      m.tools.snapshot = () => ({ admin: false, flows: [] });
      await m.tools.execute(
        "propose_app_action",
        { task: "export_session" },
        { shareIPs: false },
      );
      await m.tools.execute(
        "show_view",
        { page: "AI console" },
        { shareIPs: false },
      );
    });
    const fileReview = page
      .getByRole("region", { name: "AI action review" })
      .filter({
        has: page.getByRole("heading", {
          name: "Export traffic snapshot using Save As",
        }),
      });
    await fileReview
      .getByRole("button", { name: "Approve task", exact: true })
      .click();
    await fileReview
      .getByText("Save cancelled; no export written.", { exact: true })
      .waitFor();
    assert.deepEqual(errors, []);
    await fs.writeFile(
      `test-results/operations-smoke-${provider}${packaged ? "-packaged" : ""}.json`,
      JSON.stringify(
        {
          ok: true,
          provider,
          packaged,
          version: require("../package.json").version,
          checks: [
            "real provider adapter loop",
            "review before capture",
            "single fixed capture service",
            "local packet detail without provider disclosure",
            "view acknowledgement and filters",
            "profile view filters",
            "rule view filters",
            "non-admin export review and cancelled save",
          ],
          nativeOperations: "simulated",
          paidInference: false,
          installerExecuted: false,
          errors,
        },
        null,
        2,
      ),
    );
    console.log(
      `Operations smoke passed (${provider}, ${packaged ? "packaged" : "source"})`,
    );
  } finally {
    await app.close();
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
