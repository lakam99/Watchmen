const { _electron: electron } = require("playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const { randomUUID } = require("node:crypto");
(async () => {
  await fs.mkdir("test-results", { recursive: true });
  const workingDir = await fs.mkdtemp(
    path.join(process.cwd(), "test-results", "secure-settings-"),
  );
  const token = "synthetic-ui-test-" + randomUUID();
  const env = { ...process.env, WATCHMEN_WORKSPACE_DIR: workingDir };
  delete env.ELECTRON_RUN_AS_NODE;
  const packaged = process.argv.includes("--packaged");
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
            args: [],
          }
        : { args: [process.cwd()] }),
      env,
    });
  let app = await launch();
  let captured,
    errors = [];
  try {
    let page = await app.firstWindow();
    page.on("pageerror", (e) => errors.push(e.message));
    await page.waitForFunction(() => document.querySelector("tbody tr"));
    await page
      .getByRole("button", { name: "Applications", exact: true })
      .first()
      .click();
    await page.locator("tbody tr").first().click();
    const nested = page.getByRole("table", { name: "Individual connections" });
    await nested.waitFor();
    assert.ok((await nested.getByRole("row").count()) > 1);
    await page
      .getByRole("textbox", { name: "Search connections" })
      .fill("impossible-endpoint-999999");
    await page.getByText("No connections match this filter.").waitFor();
    await page.getByRole("textbox", { name: "Search connections" }).fill("");
    await nested.getByRole("row").nth(1).click();
    await page.getByRole("dialog", { name: "Connection inspector" }).waitFor();
    assert.equal(
      await page.getByRole("combobox", { name: "Inspect connection" }).count(),
      0,
    );
    await page.keyboard.press("Escape");
    await page.getByRole("button", { name: "Settings & privacy" }).click();
    await page.getByRole("button", { name: "Dark", exact: true }).click();
    await page.waitForFunction(
      () => document.documentElement.dataset.theme === "dark",
    );
    await page
      .getByRole("textbox", { name: "AI model", exact: true })
      .fill("openai/test-model");
    await page.getByLabel("AI API token", { exact: true }).fill(token);
    await page
      .getByRole("button", { name: "Save AI settings", exact: true })
      .click();
    await page.getByText("Token saved", { exact: true }).waitFor();
    assert.equal(
      await page.getByLabel("AI API token", { exact: true }).inputValue(),
      "",
    );
    let status = await page.evaluate(() => window.watchmen.preferences());
    assert.equal(status.ok, true);
    assert.equal(status.value.hasToken, true);
    assert.equal(status.value.ai.provider, "openrouter");
    assert.ok(!JSON.stringify(status).includes(token));
    const tokenPath = path.join(workingDir, ".watchmen", "ai-token.bin");
    const cipher = await fs.readFile(tokenPath);
    assert.ok(!cipher.includes(Buffer.from(token)));
    assert.ok(
      !(
        await fs.readFile(
          path.join(workingDir, ".watchmen", "settings.json"),
          "utf8",
        )
      ).includes(token),
    );
    await page.screenshot({ path: "test-results/secure-ai-settings-dark.png" });
    await page.getByRole("button", { name: "Back to my network" }).click();
    await app.close();
    app = await launch();
    page = await app.firstWindow();
    page.on("pageerror", (e) => errors.push(e.message));
    await page.waitForFunction(() => document.querySelector("tbody tr"));
    await page.waitForFunction(
      () => document.documentElement.dataset.theme === "dark",
    );
    status = await page.evaluate(() => window.watchmen.preferences());
    assert.equal(status.value.hasToken, true);
    await app.evaluate(({ net }) => {
      global.__aiRequest = null;
      net.fetch = async (url, options) => {
        global.__aiRequest = {
          url,
          body: options.body,
          hasAuthorization: !!options.headers.Authorization,
        };
        return new Response(
          JSON.stringify({
            choices: [
              {
                message: {
                  content:
                    "Overview\nControlled integration response.\nNotable observations\nMetadata only.\nSuggested checks\nVerify expected application activity.",
                },
              },
            ],
          }),
          { status: 200 },
        );
      };
    });
    await page
      .getByRole("button", { name: "AI insights", exact: true })
      .click();
    await page.getByRole("button", { name: "Preview data to share" }).click();
    const preview = page.locator(".ai-preview");
    await preview.waitFor();
    assert.ok((await preview.innerText()).includes("frozen at"));
    await page
      .getByRole("button", { name: "Generate insights", exact: true })
      .click();
    await page
      .getByText("Controlled integration response.", { exact: false })
      .waitFor();
    captured = await app.evaluate(() => global.__aiRequest);
    const body = JSON.parse(captured.body);
    const payload = JSON.parse(body.messages[1].content);
    assert.equal(captured.url, "https://openrouter.ai/api/v1/chat/completions");
    assert.equal(body.model, "openai/test-model");
    assert.equal(captured.hasAuthorization, true);
    assert.ok(payload.connections.length);
    assert.equal(
      payload.connections.some(
        (c) =>
          "remoteIP" in c ||
          "pid" in c ||
          "processPath" in c ||
          "localAddress" in c,
      ),
      false,
    );
    assert.ok(!JSON.stringify(payload).includes(token));
    await page
      .getByRole("button", { name: "Applications", exact: true })
      .first()
      .click();
    await page.locator("tbody tr").first().click();
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.screenshot({ path: "test-results/nested-connections-dark.png" });
    await page.getByRole("button", { name: "Settings & privacy" }).click();
    await page
      .getByRole("button", { name: "Remove token", exact: true })
      .click();
    await page.getByText("Not configured", { exact: true }).waitFor();
    status = await page.evaluate(() => window.watchmen.preferences());
    assert.equal(status.value.hasToken, false);
    await assert.rejects(() => fs.access(tokenPath));
    await page.getByRole("button", { name: "Light", exact: true }).click();
    await page.getByRole("button", { name: "Back to my network" }).click();
    await page.waitForFunction(
      () => document.documentElement.dataset.theme === "light",
    );
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
      realWindowsEncryption: true,
      checks: [
        "inline connection table and filter",
        "specific connection inspector without dropdown",
        "dark and light themes",
        "theme persisted across restart",
        "token saved through UI",
        "encrypted token contains no plaintext",
        "token decrypted after restart",
        "token absent from renderer status",
        "AI request and response with mocked provider",
        "remote IPs excluded by default",
        "OpenRouter chat-completions endpoint and model",
        "token removal",
        "minimum width",
        "no renderer exceptions",
      ],
    };
    await fs.writeFile(
      "test-results/features-smoke" + (packaged ? "-packaged" : "") + ".json",
      JSON.stringify(result, null, 2),
    );
    console.log(JSON.stringify(result, null, 2));
  } finally {
    await app.close();
    await fs
      .rm(path.join(workingDir, ".watchmen", "ai-token.bin"), { force: true })
      .catch(() => {});
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
