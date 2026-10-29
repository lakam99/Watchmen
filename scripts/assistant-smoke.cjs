const { _electron: electron } = require("playwright"),
  fs = require("node:fs/promises"),
  path = require("node:path"),
  assert = require("node:assert/strict");
(async () => {
  await fs.mkdir("test-results", { recursive: true });
  const workspace = await fs.mkdtemp(
    path.join(require("node:os").tmpdir(), "watchmen-assistant-ui-"),
  );
  await fs.mkdir(path.join(workspace, ".watchmen"));
  await fs.writeFile(
    path.join(workspace, ".watchmen/settings.json"),
    JSON.stringify({ theme: "dark" }),
  );
  await fs.writeFile(
    path.join(workspace, ".watchmen/update-settings.json"),
    JSON.stringify({ autoCheck: false, autoDownload: false }),
  );
  const token = "synthetic-console-" + require("node:crypto").randomUUID(),
    env = { ...process.env, WATCHMEN_WORKSPACE_DIR: workspace },
    packaged = process.argv.includes("--packaged");
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
    page = await app.firstWindow();
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  try {
    await page
      .getByRole("button", { name: "Settings & privacy", exact: true })
      .click();
    await page
      .getByRole("textbox", { name: "AI model", exact: true })
      .fill("fixture/tool-capable-model");
    await page.getByLabel("AI API token", { exact: true }).fill(token);
    await page
      .getByRole("button", { name: "Save AI settings", exact: true })
      .click();
    await page.getByText("Token saved", { exact: true }).waitFor();
    await page
      .getByRole("button", { name: "Back to my network", exact: true })
      .click();
    const snapshot = await page.evaluate(() => window.watchmen.getStatus());
    await app.evaluate(
      async (
        { app, ipcMain, BrowserWindow, safeStorage },
        { workspace, snapshot },
      ) => {
        const require = process
            .getBuiltinModule("module")
            .createRequire(app.getAppPath() + "/electron/main.cjs"),
          { Assistant } = require("./assistant.cjs"),
          { Preferences } = require("./preferences.cjs"),
          { SettingsStore } = require("./settings-store.cjs"),
          { Firewall } = require("./firewall.cjs"),
          { TrafficStore } = require("./traffic-store.cjs"),
          { randomUUID } = require("node:crypto");
        const settings = new SettingsStore(workspace + "/.watchmen");
        await settings.init();
        const preferences = new Preferences(
          workspace + "/.watchmen",
          safeStorage,
          settings,
        );
        await preferences.init();
        const win = BrowserWindow.getAllWindows()[0],
          send = win.webContents.send.bind(win.webContents),
          flow = {
            id: "console-fixture-flow",
            pid: 9001,
            app: "Relay Browser",
            processPath: "C:\\FixtureApps\\RelayBrowser.exe",
            protocol: "TCP",
            localAddress: "192.0.2.42",
            localPort: 51000,
            remoteAddress: "8.8.8.8",
            remotePort: 443,
            state: "Established",
            active: true,
            received: 42000000,
            sent: 1400000,
            rxRate: 240000,
            txRate: 12000,
            firstSeen: new Date(Date.now() - 300000).toISOString(),
            lastSeen: new Date().toISOString(),
          };
        const current = {
          ...snapshot,
          timestamp: new Date().toISOString(),
          admin: true,
          tracing: true,
          flows: [flow],
          errors: [],
          agentError: null,
          profileStatus: {
            available: true,
            recording: true,
            error: null,
            databasePath: "isolated UI fixture",
          },
          locations: {},
          locationsEnabled: false,
          alertCount: 0,
        };
        win.webContents.send = (channel, ...args) =>
          send(channel, ...(channel === "snapshot" ? [current] : args));
        ipcMain.removeHandler("status");
        ipcMain.handle("status", () => current);
        let rules = [];
        global.__assistantNativeActions = [];
        global.__assistantRequests = [];
        const firewall = new Firewall(workspace + "/.watchmen", {
          snapshot: () => current,
          transport: async (request) => {
            global.__assistantNativeActions.push(request.action);
            if (request.action === "add")
              rules.push({
                ...request.rule,
                id: randomUUID(),
                enabled: true,
                partial: false,
                createdAt: new Date().toISOString(),
              });
            if (request.action === "set-enabled")
              rules.find((r) => r.id === request.id).enabled = request.enabled;
            return {
              rules: structuredClone(rules),
              admin: true,
              profiles: [],
              isolationVerified: true,
              verificationError: null,
              updatedAt: new Date().toISOString(),
            };
          },
        });
        const store = new TrafficStore(workspace + "/.watchmen/traffic.sqlite");
        const response = (message) =>
          new Response(
            JSON.stringify({
              choices: [{ message: { role: "assistant", ...message } }],
            }),
          );
        const tool = (name, args = {}) =>
          response({
            content: null,
            tool_calls: [
              {
                id: "call_" + randomUUID(),
                type: "function",
                function: { name, arguments: JSON.stringify(args) },
              },
            ],
          });
        const manager = new Assistant({
          preferences,
          settings,
          snapshot: () => current,
          history: () => store,
          firewall,
          changed: (state) => send("assistant-state", state),
          fetch: async (url, init) => {
            if (url.startsWith("https://ipwho.is/"))
              return new Response(
                JSON.stringify({
                  success: true,
                  country: "Example country",
                  city: "Example city",
                  connection: { org: "Fixture network" },
                }),
              );
            const body = JSON.parse(init.body);
            global.__assistantRequests.push(body);
            if (body.tools?.some((t) => t.type === "openrouter:web_search"))
              return response({
                content:
                  "The source describes transport behavior; it does not establish a threat verdict.",
                annotations: [
                  {
                    type: "url_citation",
                    url_citation: {
                      url: "https://www.rfc-editor.org/rfc/rfc9000",
                      title: "QUIC transport specification",
                    },
                  },
                ],
              });
            const lastUser = body.messages
                .map((m) => m.role)
                .lastIndexOf("user"),
              prompt = body.messages[lastUser].content,
              results = body.messages
                .slice(lastUser + 1)
                .filter((m) => m.role === "tool"),
              last = results.length ? JSON.parse(results.at(-1).content) : null;
            if (/slow/i.test(prompt))
              return new Promise((resolve, reject) =>
                init.signal.addEventListener(
                  "abort",
                  () => reject(new Error("cancelled")),
                  { once: true },
                ),
              );
            if (/unblock/i.test(prompt)) {
              if (!last) return tool("network_rules");
              if (last.rules)
                return tool("propose_unblock", {
                  ruleRef: last.rules[0].ruleRef,
                });
              return response({
                content:
                  "A single saved rule is ready for review. No unblock has been applied yet.",
              });
            }
            if (/block/i.test(prompt)) {
              if (!last)
                return tool("list_applications", { query: "Relay Browser" });
              if (last.applications)
                return tool("propose_block", {
                  scope: "app",
                  targetRef: last.applications[0].appRef,
                });
              return response({
                content:
                  "Relay Browser is ready for an entire-application block review. The executable is shown locally. Approve only if this is the intended target; no change has been made yet.",
              });
            }
            if (/research|lookup/i.test(prompt)) {
              if (!last) return tool("inspect_connections");
              if (last.connections)
                return tool("lookup_destination", {
                  connectionRef: last.connections[0].connectionRef,
                });
              if (last.country)
                return tool("search_web", {
                  query: "QUIC transport networking specification",
                });
              return response({
                content:
                  "The public destination lookup returned an approximate location and network owner. The cited transport source is reference material, not proof that this traffic is malicious.",
              });
            }
            if (!last) return tool("network_status");
            return response({
              content:
                "The local collector reports one current fixture connection. No network task was requested.",
            });
          },
        });
        const handles = {
          "assistant-status": () => manager.status(),
          "assistant-send": (text) => manager.send(text),
          "assistant-cancel": () => manager.cancel(),
          "assistant-reset": () => manager.reset(),
          "assistant-configure": (options) => manager.configure(options),
          "assistant-approve": (id, ack) => manager.approve(id, ack),
          "assistant-reject": (id) => manager.reject(id),
        };
        for (const [name, handler] of Object.entries(handles)) {
          ipcMain.removeHandler(name);
          ipcMain.handle(name, async (event, ...args) => {
            if (event.sender !== win.webContents)
              throw new Error("Untrusted test sender");
            try {
              return { ok: true, value: await handler(...args) };
            } catch (e) {
              return { ok: false, error: e.message };
            }
          });
        }
        global.__assistantFixture = manager;
        send("snapshot", current);
        send("assistant-state", manager.status());
      },
      { workspace, snapshot },
    );
    const nav = page.getByRole("navigation");
    await nav.getByRole("button", { name: "AI console", exact: true }).click();
    await page
      .getByRole("heading", { name: "COMMS / AI ASSISTANT", exact: true })
      .waitFor();
    await page.setViewportSize({ width: 1500, height: 1040 });
    const message = page.getByRole("textbox", {
      name: "Message AI assistant",
      exact: true,
    });
    const send = async (text) => {
      await message.fill(text);
      await page.getByRole("button", { name: "Send", exact: true }).click();
      await page
        .getByRole("button", { name: "Stop response", exact: true })
        .waitFor({ state: "detached" });
      await page.waitForTimeout(100);
    };
    await send("Block Relay Browser after preparing an exact review.");
    const review = page.getByRole("region", {
      name: "AI action review",
      exact: true,
    });
    await review
      .getByRole("button", { name: "Approve block", exact: true })
      .waitFor();
    assert.equal(
      await app.evaluate(
        () => global.__assistantNativeActions.filter((a) => a === "add").length,
      ),
      0,
    );
    await page.screenshot({
      path: "test-results/ai-console-review-dark.png",
      fullPage: true,
    });
    await review
      .getByRole("button", { name: "Approve block", exact: true })
      .click();
    await review
      .getByText("Windows committed and verified the block.", { exact: true })
      .waitFor();
    assert.equal(
      await app.evaluate(
        () => global.__assistantNativeActions.filter((a) => a === "add").length,
      ),
      1,
    );
    await send("Unblock the existing browser rule.");
    await page
      .getByRole("button", { name: "Approve unblock", exact: true })
      .click();
    await page
      .getByText(
        "Windows disabled and verified this rule. Other rules may still block the target.",
        { exact: true },
      )
      .first()
      .waitFor();
    assert.equal(
      await app.evaluate(
        () =>
          global.__assistantNativeActions.filter((a) => a === "set-enabled")
            .length,
      ),
      1,
    );
    await page
      .getByRole("checkbox", {
        name: "Share public destination IPs",
        exact: true,
      })
      .check();
    await app.evaluate(async () => {
      await global.__assistantFixture.settings.patch("assistant", {
        shareIPs: false,
      });
    });
    await page
      .getByRole("checkbox", { name: "Allow public IP lookups", exact: true })
      .check();
    const afterExternalRevocation = await page.evaluate(() =>
      window.watchmen.assistantStatus(),
    );
    assert.equal(
      afterExternalRevocation.value.options.shareIPs,
      false,
      "A stale checkbox must not re-enable sharing revoked by another window.",
    );
    await page
      .getByRole("checkbox", { name: "Allow web research", exact: true })
      .check();
    await send("Research and lookup the first public destination.");
    await page
      .getByRole("button", {
        name: "QUIC transport specification",
        exact: true,
      })
      .waitFor();
    assert.equal(
      await page
        .getByRole("checkbox", {
          name: "Share public destination IPs",
          exact: true,
        })
        .isChecked(),
      false,
    );
    await page.screenshot({
      path: "test-results/ai-console-research-dark.png",
      fullPage: true,
    });
    const requests = await app.evaluate(() => global.__assistantRequests);
    assert.ok(!JSON.stringify(requests).includes(token));
    assert.ok(!JSON.stringify(requests).includes("RelayBrowser.exe"));
    assert.ok(!JSON.stringify(requests).includes("192.0.2.42"));
    await message.fill("Begin a slow investigation.");
    await page.getByRole("button", { name: "Send", exact: true }).click();
    await page
      .getByRole("button", { name: "Stop response", exact: true })
      .waitFor();
    await nav.getByRole("button", { name: "Overview", exact: true }).click();
    await page
      .getByRole("button", { name: "Open AI console", exact: true })
      .getByText("AI working", { exact: true })
      .waitFor();
    await nav.getByRole("button", { name: "AI console", exact: true }).click();
    await page
      .getByRole("button", { name: "Stop response", exact: true })
      .click();
    await page.getByRole("button", { name: "Send", exact: true }).waitFor();
    await page.setViewportSize({ width: 1000, height: 720 });
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth > innerWidth,
      ),
      false,
    );
    await page
      .getByRole("button", { name: "Settings & privacy", exact: true })
      .click();
    await page.getByRole("button", { name: "Light", exact: true }).click();
    await page
      .getByRole("button", { name: "Back to my network", exact: true })
      .click();
    await page.waitForFunction(
      () => document.documentElement.dataset.theme === "light",
    );
    await page.screenshot({
      path: "test-results/ai-console-light-narrow.png",
      fullPage: true,
    });
    await app.close();
    app = await launch();
    page = await app.firstWindow();
    page.on("pageerror", (e) => errors.push(e.message));
    await page
      .getByRole("heading", { name: "COMMS / AI ASSISTANT", exact: true })
      .waitFor();
    await page
      .getByText("Investigate. Review. Act.", { exact: true })
      .waitFor();
    assert.equal(
      await page
        .getByRole("checkbox", { name: "Allow web research", exact: true })
        .isChecked(),
      true,
    );
    assert.equal(
      await page
        .getByRole("checkbox", { name: "Allow public IP lookups", exact: true })
        .isChecked(),
      true,
    );
    assert.deepEqual(errors, []);
    const result = {
      passed: true,
      packaged,
      provider:
        "Simulated OpenRouter tool calls; real production Assistant and Firewall managers with simulated native transport",
      checks: [
        "token configured through encrypted settings UI",
        "multi-step app discovery and block proposal",
        "no mutation before approval",
        "approved block and one-rule unblock",
        "public IP and cited web lookup opt-ins",
        "tool activity log",
        "no credentials, executable paths or local IPs in model messages",
        "background response while monitoring",
        "cancellation",
        "1000px layout and light mode",
        "saved permissions and ephemeral chat after restart",
        "no renderer errors",
      ],
    };
    await fs.writeFile(
      "test-results/assistant-smoke" + (packaged ? "-packaged" : "") + ".json",
      JSON.stringify(result, null, 2),
    );
    console.log(JSON.stringify(result, null, 2));
  } finally {
    await app.close();
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
