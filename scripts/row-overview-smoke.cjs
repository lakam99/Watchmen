const { _electron: electron } = require("playwright");
const fs = require("node:fs/promises"),
  path = require("node:path"),
  assert = require("node:assert/strict");
(async () => {
  await fs.mkdir("test-results", { recursive: true });
  const workspace = await fs.mkdtemp(
    path.join(require("node:os").tmpdir(), "watchmen-row-overview-"),
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
  const packaged = process.argv.includes("--packaged"),
    env = { ...process.env, WATCHMEN_WORKSPACE_DIR: workspace };
  delete env.ELECTRON_RUN_AS_NODE;
  const args = ["--user-data-dir=" + path.join(workspace, "chromium")];
  const app = await electron.launch({
    ...(packaged
      ? {
          executablePath: path.resolve(
            "release",
            require("../package.json").version,
            "Watchmen-win32-x64/Watchmen.exe",
          ),
          args,
        }
      : { args: [process.cwd(), ...args] }),
    env,
    timeout: 60000,
  });
  const errors = [],
    tested = new Set();
  try {
    const page = await app.firstWindow();
    page.on("pageerror", (e) => errors.push(e.message));
    await page.waitForFunction(() => window.watchmen);
    const snapshot = await page.evaluate(() => window.watchmen.getStatus());
    await app.evaluate(
      ({ app, ipcMain, BrowserWindow, net, shell }, snapshot) => {
        const win = BrowserWindow.getAllWindows()[0],
          send = win.webContents.send.bind(win.webContents),
          now = Date.now();
        const flow = {
          id: "row-flow",
          app: "Relay Browser",
          processPath: "C:\\Fixture Apps\\RelayBrowser.exe",
          pid: 9001,
          remoteAddress: "198.51.100.44",
          localAddress: "192.168.1.77",
          remotePort: 443,
          localPort: 50123,
          protocol: "TCP",
          state: "Established",
          active: true,
          received: 0,
          sent: 0,
          rxRate: 0,
          txRate: 0,
          firstSeen: new Date(now).toISOString(),
          lastSeen: new Date(now).toISOString(),
        };
        const current = {
          ...snapshot,
          timestamp: new Date(now).toISOString(),
          flows: [flow],
          tracing: false,
          admin: false,
          locationsEnabled: true,
          locations: {
            [flow.remoteAddress]: {
              country: "Canada",
              code: "CA",
              city: "Example city",
              org: "Fixture network",
            },
          },
          alertCount: 1,
        };
        win.webContents.send = (channel, ...args) =>
          send(channel, ...(channel === "snapshot" ? [current] : args));
        ipcMain.removeHandler("status");
        ipcMain.handle("status", () => current);
        const profileApp = {
          id: "profile-app",
          name: flow.app,
          path: flow.processPath,
          firstSeen: now - 60000,
          lastSeen: now,
          received: 1000,
          sent: 200,
          observations: 4,
          measuredMs: 2000,
          observedMs: 60000,
          sessions: 1,
          destinations: 1,
        };
        const destination = {
          address: flow.remoteAddress,
          scope: "internet",
          country: "Canada",
          city: "Example city",
          org: "Fixture network",
          firstSeen: now - 60000,
          lastSeen: now,
          received: 1000,
          sent: 200,
          observations: 4,
          measuredMs: 2000,
          applications: 1,
          services: 1,
        };
        const profile = {
          databasePath: "Fixture traffic database",
          schemaVersion: 1,
          range: "all",
          updatedAt: now,
          firstSeen: now - 60000,
          recording: true,
          eventsLost: 0,
          totals: {
            applications: 1,
            destinations: 1,
            received: 1000,
            sent: 200,
            observations: 4,
            measuredMs: 2000,
            sessions: 1,
          },
          applications: [profileApp],
          destinations: [destination],
          daily: [],
          protocols: [{ protocol: "TCP", observations: 4, applications: 1 }],
          countries: [{ country: "Canada", destinations: 1 }],
        };
        const change = {
          id: "row-change",
          type: "new_destination",
          app_id: profileApp.id,
          app_name: flow.app,
          address: flow.remoteAddress,
          severity: "notice",
          observed_at: now,
          last_seen: now,
          occurrences: 1,
          status: "open",
          evidence: {
            summary: "A new destination was observed.",
            baseline: {},
            observed: {},
            note: "Fixture change",
          },
          explanation: null,
        };
        const packet = {
          id: "row-packet",
          timestamp: now,
          protocol: "TCP",
          source: flow.localAddress,
          destination: flow.remoteAddress,
          sourcePort: 50123,
          destinationPort: 443,
          direction: "outbound",
          app: flow.app,
          summary: "private-packet-summary",
          length: 120,
          capturedLength: 120,
          truncated: false,
          encrypted: true,
          headers: [{ name: "Authorization", value: "private-header" }],
          payloadText: "private-packet-content",
        };
        const rule = {
          id: "row-rule",
          kind: "app",
          label: "Relay Browser",
          appPath: flow.processPath,
          address: "",
          protocol: "",
          port: 0,
          countries: [],
          sourceMonth: "",
          rangeCount: 0,
          nativeRuleCount: 2,
          enabled: true,
          partial: false,
          createdAt: new Date(now).toISOString(),
        };
        const handlers = {
          "traffic-profile": () => profile,
          "traffic-profile-app": () => ({
            application: profileApp,
            endpoints: [
              {
                ...destination,
                protocol: "TCP",
                port: 443,
                localServicePort: 0,
              },
            ],
          }),
          "alerts-list": () => ({
            alerts: [change],
            counts: { total: 1, open: 1, spikes: 0 },
            learning: {
              eligibleApps: 1,
              minimumObservedMs: 60000,
              minimumMeasuredMinutes: 5,
            },
            updatedAt: now,
          }),
          "packets-status": () => ({
            active: false,
            processing: false,
            error: null,
            source: "Fixture capture",
            startedAt: now,
            endsAt: null,
            packets: [packet],
            totalRecords: 1,
            displayLimit: 100,
            limited: false,
          }),
          "firewall-status": () => ({
            rules: [rule],
            admin: false,
            profiles: [],
            isolationVerified: true,
            verificationError: null,
            updatedAt: new Date(now).toISOString(),
            error: null,
            busy: false,
            phase: "idle",
          }),
          "firewall-catalog": () => ({
            countries: [],
            regions: [],
            attribution: "Fixture",
            source: "Fixture",
            month: "2026-10",
          }),
        };
        for (const [name, handler] of Object.entries(handlers)) {
          ipcMain.removeHandler(name);
          ipcMain.handle(name, (event) => {
            if (event.sender !== win.webContents)
              throw new Error("Untrusted test sender");
            return { ok: true, value: handler() };
          });
        }
        global.__rowRequests = [];
        global.__rowMutations = 0;
        global.__rowMode = "normal";
        global.__rowWebMode = "normal";
        global.__rowOpened = [];
        shell.openExternal = async (url) => {
          global.__rowOpened.push(url);
        };
        for (const name of [
          "firewall-apply",
          "firewall-toggle",
          "firewall-forget",
          "firewall-unblock-all",
        ]) {
          ipcMain.removeHandler(name);
          ipcMain.handle(name, () => {
            global.__rowMutations++;
            throw new Error("No native changes allowed in this check");
          });
        }
        net.fetch = async (url, init) => {
          if (
            ![
              "https://api.openai.com/v1/responses",
              "https://openrouter.ai/api/v1/chat/completions",
            ].includes(url)
          )
            throw new Error("Unexpected lookup endpoint");
          const body = JSON.parse(init.body);
          global.__rowRequests.push({ url, body });
          const web = body.tools?.some((t) =>
            ["web_search", "openrouter:web_search"].includes(t.type),
          );
          if (web) {
            if (global.__rowWebMode === "slow")
              return new Promise((_, reject) =>
                init.signal.addEventListener(
                  "abort",
                  () => {
                    global.__rowWebAborted = true;
                    reject(new Error("aborted"));
                  },
                  { once: true },
                ),
              );
            const text =
                "Relay Browser is a fixture browser application that commonly uses the network to load web pages. A name match does not verify the local executable.",
              citation = {
                type: "url_citation",
                url: "https://example.com/relay-browser",
                title: "Fixture app documentation",
              },
              annotations = global.__rowWebMode === "missing" ? [] : [citation];
            return new Response(
              JSON.stringify(
                url.endsWith("/responses")
                  ? {
                      status: "completed",
                      output: [
                        {
                          type: "web_search_call",
                          status: "completed",
                          action: { type: "search" },
                        },
                        {
                          type: "message",
                          role: "assistant",
                          content: [{ type: "output_text", text, annotations }],
                        },
                      ],
                    }
                  : {
                      choices: [
                        {
                          message: {
                            role: "assistant",
                            content: text,
                            annotations: annotations.map((c) => ({
                              type: "url_citation",
                              url_citation: c,
                            })),
                          },
                        },
                      ],
                    },
              ),
            );
          }
          if (global.__rowMode === "fail")
            return new Response("do-not-echo-provider-error", { status: 429 });
          if (global.__rowMode === "slow")
            return new Promise((_, reject) =>
              init.signal.addEventListener(
                "abort",
                () => reject(new Error("aborted")),
                { once: true },
              ),
            );
          const input = JSON.parse(body.input || body.messages[1].content);
          const text = `This ${input.rowType.replaceAll("_", " ")} row summarizes observed network metadata. Verify that the activity matches the application's expected purpose; the metadata alone does not establish a threat.`;
          return new Response(
            JSON.stringify(
              url.endsWith("/responses")
                ? {
                    status: "completed",
                    output: [
                      {
                        type: "message",
                        content: [{ type: "output_text", text }],
                      },
                    ],
                  }
                : { choices: [{ message: { content: text } }] },
            ),
          );
        };
        send("snapshot", current);
      },
      snapshot,
    );
    const nav = page.getByRole("navigation"),
      dialog = page.getByRole("dialog", { name: "What is this?", exact: true });
    await nav
      .getByRole("button", { name: "Applications", exact: true })
      .click();
    const first = page.locator("tr[data-ai-row]").first();
    await first.click({ button: "right" });
    assert.equal(
      await page.getByRole("table", { name: "Individual connections" }).count(),
      0,
    );
    assert.equal(await app.evaluate(() => global.__rowRequests.length), 0);
    await page
      .getByRole("menuitem", { name: "What is this?", exact: true })
      .click();
    await dialog
      .getByText("Add an API token in Settings to use AI overviews.")
      .waitFor();
    assert.equal(await app.evaluate(() => global.__rowRequests.length), 0);
    await dialog
      .getByRole("button", { name: "Set up AI", exact: true })
      .click();
    await page
      .getByRole("combobox", { name: "AI provider" })
      .selectOption("openai");
    const token = "synthetic-row-ui-" + require("node:crypto").randomUUID();
    await page.getByLabel("AI API token", { exact: true }).fill(token);
    await page
      .getByRole("button", { name: "Save AI settings", exact: true })
      .click();
    await page.getByText("Token saved", { exact: true }).waitFor();
    await page
      .getByRole("button", { name: "Back to my network", exact: true })
      .click();
    async function explain(row, kind, keyboard = false) {
      await row.waitFor();
      if (keyboard) {
        await row.focus();
        await page.keyboard.press("Shift+F10");
      } else await row.click({ button: "right" });
      const menu = page.getByRole("menu", { name: "Row actions" });
      await menu.waitFor();
      const bounds = await menu.boundingBox();
      const size = page.viewportSize();
      assert.ok(
        bounds.x >= 0 &&
          bounds.y >= 0 &&
          bounds.x + bounds.width <= size.width &&
          bounds.y + bounds.height <= size.height,
      );
      await page
        .getByRole("menuitem", { name: "What is this?", exact: true })
        .click();
      await dialog.locator(".row-ai-answer").waitFor();
      assert.ok(
        (await dialog.locator(".row-ai-answer").innerText()).includes(
          kind.replaceAll("_", " "),
        ),
      );
      tested.add(kind);
      await page.keyboard.press("Escape");
      await dialog.waitFor({ state: "detached" });
    }
    await page.setViewportSize({ width: 1480, height: 960 });
    await page.waitForTimeout(150);
    await explain(first, "application", true);
    await first.click();
    await explain(
      page
        .getByRole("table", { name: "Individual connections" })
        .locator("tbody tr")
        .first(),
      "connection",
    );
    for (const [name, kind] of [
      ["Destinations", "destination"],
      ["Locations", "country"],
      ["Connections", "protocol"],
    ]) {
      await nav.getByRole("button", { name, exact: true }).click();
      await explain(page.locator("tr[data-ai-row]").first(), kind);
    }
    await nav
      .getByRole("button", { name: "Traffic profile", exact: true })
      .click();
    const appRow = page
      .getByRole("table", { name: "Saved application profiles" })
      .locator("tbody tr")
      .first();
    await explain(appRow, "profile_app");
    await appRow.click();
    await explain(
      page
        .getByRole("table", { name: "Saved application services" })
        .locator("tbody tr")
        .first(),
      "profile_service",
    );
    await page
      .getByRole("button", { name: "Destination profiles", exact: true })
      .click();
    await explain(
      page
        .getByRole("table", { name: "Saved destination profiles" })
        .locator("tbody tr")
        .first(),
      "profile_destination",
    );
    for (const [name, kind, table] of [
      ["Changes", "change", "Saved connection changes"],
      ["Packets", "packet", "Captured packets"],
      ["Network rules", "rule", "Saved network rules"],
    ]) {
      await nav.getByRole("button", { name, exact: true }).click();
      await explain(
        page.getByRole("table", { name: table }).locator("tbody tr").first(),
        kind,
      );
    }
    await nav
      .getByRole("button", { name: "Applications", exact: true })
      .click();
    const row = page.locator("tr[data-ai-row]").first();
    await row.click({ button: "right" });
    await page.keyboard.press("Escape");
    assert.equal(await page.getByRole("menu").count(), 0);
    await row.click({ button: "right" });
    await page.getByRole("menuitem", { name: "What is this?" }).click();
    await dialog.locator(".row-ai-answer").waitFor();
    const beforeResearch = await app.evaluate(
      () => global.__rowRequests.length,
    );
    await dialog
      .getByRole("button", { name: "Research app on web", exact: true })
      .click();
    await dialog.getByText(/Web researched/).waitFor();
    assert.equal(
      await app.evaluate(() => global.__rowRequests.length),
      beforeResearch + 1,
    );
    await dialog
      .getByRole("button", {
        name: "Open source 1: Fixture app documentation",
        exact: true,
      })
      .click();
    assert.deepEqual(await app.evaluate(() => global.__rowOpened), [
      "https://example.com/relay-browser",
    ]);
    const arbitrary = await page.evaluate(() =>
      window.watchmen.rowOverviewSource("https://arbitrary.example/"),
    );
    assert.equal(arbitrary.ok, false);
    await page.screenshot({ path: "test-results/row-overview-dark.png" });
    await dialog.getByRole("button", { name: "Close row overview" }).click();
    await app.evaluate(() => {
      global.__rowMode = "fail";
    });
    await row.click({ button: "right" });
    await page.getByRole("menuitem", { name: "What is this?" }).click();
    await dialog.getByRole("alert").filter({ hasText: "rate limit" }).waitFor();
    await page.keyboard.press("Escape");
    await app.evaluate(() => {
      global.__rowMode = "slow";
    });
    await row.click({ button: "right" });
    await page.getByRole("menuitem", { name: "What is this?" }).click();
    await dialog.getByRole("status").waitFor();
    await page.waitForFunction(() =>
      document
        .querySelector(".row-ai-dialog footer")
        ?.textContent?.includes("openai"),
    );
    await page.waitForTimeout(100);
    await page.keyboard.press("Escape");
    await app.evaluate(() => {
      global.__rowMode = "normal";
    });
    // A failed isolated search keeps the original row explanation and remains retryable.
    await row.click({ button: "right" });
    await page.getByRole("menuitem", { name: "What is this?" }).click();
    await dialog.locator(".row-ai-answer").waitFor();
    await app.evaluate(() => (global.__rowWebMode = "missing"));
    await dialog
      .getByRole("button", { name: "Research app on web", exact: true })
      .click();
    await dialog.getByText(/no verifiable sources/).waitFor();
    assert.ok(await dialog.locator(".row-ai-answer").isVisible());
    await app.evaluate(() => (global.__rowWebMode = "slow"));
    await dialog
      .getByRole("button", { name: "Research app on web", exact: true })
      .click();
    await dialog
      .getByText("Researching app on web…", { exact: true })
      .waitFor();
    await page.keyboard.press("Escape");
    await app.evaluate(() => {
      global.__rowWebMode = "normal";
    });
    await page
      .getByRole("button", { name: "Settings & privacy", exact: true })
      .click();
    await page
      .getByRole("combobox", { name: "AI provider" })
      .selectOption("openrouter");
    await page.getByLabel("AI API token", { exact: true }).fill(token);
    await page
      .getByRole("button", { name: "Save AI settings", exact: true })
      .click();
    await page.getByText("Token saved", { exact: true }).waitFor();
    await page.getByRole("button", { name: "Light", exact: true }).click();
    await page
      .getByRole("button", { name: "Back to my network", exact: true })
      .click();
    await page.setViewportSize({ width: 1000, height: 720 });
    await row.click({ button: "right" });
    await page.getByRole("menuitem", { name: "What is this?" }).click();
    await dialog.locator(".row-ai-answer").waitFor();
    await dialog
      .getByRole("button", { name: "Research app on web", exact: true })
      .click();
    await dialog.getByText(/Web researched/).waitFor();
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth > innerWidth,
      ),
      false,
    );
    await page.screenshot({ path: "test-results/row-overview-light.png" });
    await page.keyboard.press("Escape");
    const allowed = await page.evaluate(() =>
      window.watchmen.assistantConfigure({ webSearch: true }),
    );
    assert.equal(allowed.ok, true);
    const beforeAuto = await app.evaluate(() => global.__rowRequests.length);
    await row.click({ button: "right" });
    await page.getByRole("menuitem", { name: "What is this?" }).click();
    await dialog.getByText(/Web researched/).waitFor();
    assert.equal(
      await app.evaluate(() => global.__rowRequests.length),
      beforeAuto + 2,
    );
    await page.keyboard.press("Escape");
    await page.evaluate(() =>
      window.watchmen.assistantConfigure({ webSearch: false }),
    );
    const captured = await app.evaluate(() => ({
      requests: global.__rowRequests,
      mutations: global.__rowMutations,
    }));
    const sent = JSON.stringify(captured.requests);
    for (const forbidden of [
      token,
      "198.51.100.44",
      "192.168.1.77",
      "Fixture Apps",
      "private-packet",
      "private-header",
      "do-not-echo-provider-error",
    ])
      assert.ok(!sent.includes(forbidden));
    assert.equal(captured.mutations, 0);
    assert.equal(tested.size, 11);
    assert.deepEqual(errors, []);
    const result = {
      passed: true,
      packaged,
      rowTypes: [...tested],
      providers: ["openai", "openrouter"],
      requests: captured.requests.length,
      nativeMutations: 0,
      checks: [
        "all data-table types and nested rows",
        "right-click without row activation or implicit request",
        "unconfigured setup",
        "keyboard menu and dismissal",
        "bounded private-data exclusion",
        "read-only provider requests",
        "app context plus one-time cited research with both providers",
        "existing web opt-in enables automatic app research",
        "app-name-only query without row metadata or packet data",
        "validated citation opening rejects arbitrary URLs",
        "research failure preserves overview; cancellation aborts web request",
        "scoped cancellation and error state",
        "dark/light and minimum-width layouts",
        "no renderer errors",
      ],
      providerRepliesSimulated: true,
    };
    await fs.writeFile(
      "test-results/row-overview-smoke" +
        (packaged ? "-packaged" : "") +
        ".json",
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
