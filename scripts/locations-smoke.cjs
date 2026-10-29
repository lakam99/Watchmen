const { _electron: electron } = require("playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const { isPublicIP } = require("../electron/network.cjs");
(async () => {
  const env = { ...process.env };
  env.WATCHMEN_WORKSPACE_DIR = require("node:path").join(
    process.cwd(),
    "test-results",
    "locations-workspace",
  );
  delete env.ELECTRON_RUN_AS_NODE;
  const app = await electron.launch({ args: [process.cwd()], env });
  try {
    const page = await app.firstWindow();
    await page.waitForFunction(async () => {
      const s = await window.watchmen.getStatus();
      return s.flows?.length > 0;
    });
    // Probe the provider using a known public DNS address, not a captured destination.
    const probe = await app.evaluate(async ({ net }) => {
      try {
        const r = await net.fetch("https://ipwho.is/8.8.8.8", {
          signal: AbortSignal.timeout(8000),
        });
        const b = await r.json();
        return {
          status: r.status,
          success: b.success === true,
          hasCountry: !!b.country,
        };
      } catch (e) {
        return { error: e.message };
      }
    });
    // Exercise opt-in, country grouping, local-address exclusions and provider limits
    // with a mocked provider so the test never submits real captured endpoints.
    await app.evaluate(({ net }) => {
      global.__lookupRequests = [];
      net.fetch = async (url) => {
        global.__lookupRequests.push(url);
        return new Response(
          JSON.stringify({
            success: true,
            country: "Test Country",
            country_code: "TC",
            city: "Test City",
            connection: { org: "Test Network" },
          }),
          { status: 200 },
        );
      };
    });
    await page.getByRole("button", { name: "Settings & privacy" }).click();
    await page
      .getByRole("button", { name: "IP location lookup", exact: true })
      .click();
    await page.getByRole("button", { name: "Back to my network" }).click();
    await page.waitForFunction(
      async () =>
        Object.keys((await window.watchmen.getStatus()).locations).length > 0,
    );
    await page.getByRole("button", { name: "Countries", exact: true }).click();
    await page.getByRole("row", { name: /Test Country/ }).waitFor();
    let status = await page.evaluate(() => window.watchmen.getStatus());
    assert.ok(status.locationsEnabled);
    assert.ok(
      Object.values(status.locations).some(
        (g) => g.city === "Test City" && g.org === "Test Network",
      ),
    );
    const requests = await app.evaluate(() => global.__lookupRequests);
    assert.ok(requests.length);
    for (const url of requests)
      assert.ok(
        isPublicIP(decodeURIComponent(url.split("/").at(-1))),
        "Private address must never be looked up",
      );
    await app.evaluate(({ net }) => {
      net.fetch = async () =>
        new Response("{}", { status: 429, headers: { "retry-after": "60" } });
    });
    await page.waitForFunction(async () =>
      (await window.watchmen.getStatus()).locationStatus.includes("rate limit"),
    );
    await page.getByRole("button", { name: "Settings & privacy" }).click();
    await page
      .getByRole("button", { name: "IP location lookup", exact: true })
      .click();
    await page.getByRole("button", { name: "Back to my network" }).click();
    status = await page.evaluate(() => window.watchmen.getStatus());
    assert.equal(status.locationsEnabled, false);
    assert.deepEqual(status.locations, {});
    const result = {
      passed: true,
      liveProviderProbe: probe,
      mockedIntegration: [
        "opt-in lookup",
        "country grouping",
        "city and owner fields",
        "public addresses only",
        "429 rate-limit pause",
        "opt-out hides locations",
      ],
    };
    await fs.writeFile(
      "test-results/locations-smoke.json",
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
