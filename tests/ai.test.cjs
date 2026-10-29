const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { Preferences, validateAI } = require("../electron/preferences.cjs");
const { Insights, buildPayload } = require("../electron/insights.cjs");
const config = {
  provider: "openai",
  baseUrl: "https://api.openai.com/v1",
  model: "test-model",
};
const flow = {
  id: "a",
  pid: 59231,
  app: "Browser",
  processPath: "C:/private-user/browser.exe",
  protocol: "TCP",
  localAddress: "192.168.77.66",
  localPort: 50123,
  remoteAddress: "8.8.8.8",
  remotePort: 443,
  state: "Established",
  received: 1200,
  sent: 600,
  rxRate: 300,
  txRate: 100,
};
const snapshot = {
  timestamp: "2026-10-28T19:00:00Z",
  tracing: false,
  flows: [flow],
  locations: {},
  eventsLost: 0,
  evictedFlows: 0,
};
test("AI payload is bounded and excludes addresses, paths and process IDs by default", () => {
  const payload = buildPayload(
    {
      ...snapshot,
      flows: Array.from({ length: 200 }, (_, i) => ({
        ...flow,
        id: String(i),
      })),
    },
    { flowIds: Array.from({ length: 200 }, (_, i) => String(i)) },
  );
  assert.equal(payload.sampledConnections, 120);
  assert.equal(payload.selectedConnections, 200);
  assert.equal(payload.connections[0].received, null);
  const serialized = JSON.stringify(payload);
  for (const excluded of [
    flow.localAddress,
    flow.remoteAddress,
    flow.processPath,
    String(flow.pid),
  ])
    assert.ok(
      !serialized.includes(excluded),
      "Private metadata must be absent",
    );
  assert.equal(
    buildPayload(snapshot, { flowIds: ["a"], includeIPs: true }).connections[0]
      .remoteIP,
    "8.8.8.8",
  );
  assert.throws(
    () => buildPayload(snapshot, { flowIds: [] }),
    /Select traffic/,
  );
});
test("saved application baseline keeps paths and endpoint IPs out of the AI request", () => {
  const p = buildPayload(
    {
      ...snapshot,
      profileBaseline: [
        {
          app: "Browser",
          firstSeen: 1,
          lastSeen: 2,
          daysObserved: 3,
          sessions: 4,
          destinations: 5,
          received: 600,
          sent: 100,
          processPath: "C:/private/executable",
          address: "8.8.8.8",
          usualPorts: [
            {
              protocol: "TCP",
              port: 443,
              observations: 12,
              remoteIP: "8.8.8.8",
            },
          ],
        },
      ],
    },
    { flowIds: ["a"] },
  );
  assert.equal(p.savedApplicationProfiles[0].sessions, 4);
  assert.equal(p.savedApplicationProfiles[0].usualPorts[0].port, 443);
  assert.ok(!JSON.stringify(p.savedApplicationProfiles).includes("8.8.8.8"));
  assert.ok(!JSON.stringify(p.savedApplicationProfiles).includes("C:/private"));
});
test("provider URLs enforce HTTPS and cannot carry embedded secrets", () => {
  for (const baseUrl of [
    "http://example.com/v1",
    "https://user:password@example.com",
    "https://example.com?token=x",
    "https://example.com/#secret",
  ])
    assert.throws(() =>
      validateAI({ ...config, provider: "compatible", baseUrl }),
    );
  assert.equal(
    validateAI({ ...config, baseUrl: "https://bad.example" }).baseUrl,
    "https://api.openai.com/v1",
  );
});
test("credential persistence, rotation, endpoint binding, removal and fail-closed storage", async () => {
  const dir = await fs.mkdtemp(
    path.join(os.tmpdir(), "watchmen-credentials-test-"),
  );
  const key = crypto.randomBytes(32);
  const safe = {
    isAsyncEncryptionAvailable: async () => true,
    encryptStringAsync: async (s) => {
      const iv = crypto.randomBytes(12);
      const c = crypto.createCipheriv("aes-256-gcm", key, iv);
      const encrypted = Buffer.concat([c.update(s), c.final()]);
      return Buffer.concat([iv, c.getAuthTag(), encrypted]);
    },
    decryptStringAsync: async (b) => {
      const c = crypto.createDecipheriv("aes-256-gcm", key, b.subarray(0, 12));
      c.setAuthTag(b.subarray(12, 28));
      return {
        result: Buffer.concat([c.update(b.subarray(28)), c.final()]).toString(),
      };
    },
  };
  try {
    const p = new Preferences(dir, safe);
    await p.init();
    await p.saveAI({ ...config, token: "synthetic-unit-test-token" });
    const bytes = await fs.readFile(p.tokenPath);
    assert.ok(!bytes.includes(Buffer.from("synthetic-unit-test-token")));
    assert.ok(
      !(await fs.readFile(p.settingsPath, "utf8")).includes(
        "synthetic-unit-test-token",
      ),
    );
    assert.ok(
      !JSON.stringify(await p.status()).includes("synthetic-unit-test-token"),
    );
    await p.setTheme("dark");
    const next = new Preferences(dir, safe);
    await next.init();
    assert.equal((await next.status()).theme, "dark");
    assert.equal((await next.credential()).token, "synthetic-unit-test-token");
    await assert.rejects(
      () =>
        next.saveAI({
          ...config,
          provider: "compatible",
          baseUrl: "https://other.example/v1",
          token: "",
        }),
      /new token/,
    );
    assert.equal((await next.credential()).baseUrl, config.baseUrl);
    await next.saveAI({ ...config, token: "replacement-synthetic-token" });
    assert.equal(
      (await next.credential()).token,
      "replacement-synthetic-token",
    );
    await next.removeToken();
    assert.equal((await next.status()).hasToken, false);
    const blocked = new Preferences(dir, {
      ...safe,
      isAsyncEncryptionAvailable: async () => false,
    });
    await blocked.init();
    await assert.rejects(
      () => blocked.saveAI({ ...config, token: "not-saved" }),
      /unavailable/,
    );
    await assert.rejects(() => fs.access(blocked.tokenPath));
  } finally {
    assert.equal(path.dirname(dir), os.tmpdir());
    assert.ok(path.basename(dir).startsWith("watchmen-credentials-test-"));
    await fs.rm(dir, { recursive: true, force: true });
  }
});
test("AI request uses frozen preview, provider-bound bearer auth and no stored OpenAI response", async () => {
  let sent;
  const preferences = {
    credential: async () => ({ ...config, token: "synthetic-test-key" }),
  };
  const ai = new Insights(preferences, async (url, options) => {
    sent = { url, ...options };
    return new Response(
      JSON.stringify({
        output: [
          {
            type: "message",
            content: [
              {
                type: "output_text",
                text: "Observed traffic; verify synthetic-test-key manually.",
              },
            ],
          },
        ],
      }),
    );
  });
  const preview = ai.prepare(snapshot, { flowIds: ["a"] });
  snapshot.flows[0].sent = 9999;
  const result = await ai.run(preview.id);
  const body = JSON.parse(sent.body);
  assert.equal(sent.url, "https://api.openai.com/v1/responses");
  assert.equal(sent.headers.Authorization, "Bearer synthetic-test-key");
  assert.equal(body.store, false);
  assert.equal(JSON.parse(body.input).connections[0].sent, null);
  assert.equal(sent.redirect, "error");
  assert.ok(!result.text.includes("synthetic-test-key"));
  await assert.rejects(() => ai.run(preview.id), /Preview/);
});
test("provider failure and network errors never echo credentials; only one review can run", async () => {
  const preferences = {
    credential: async () => ({ ...config, token: "synthetic-secret" }),
  };
  for (const mode of ["401", "network"]) {
    const ai = new Insights(preferences, async () => {
      if (mode === "network") throw new Error("transport synthetic-secret");
      return new Response("synthetic-secret", { status: 401 });
    });
    const p = ai.prepare(snapshot, { flowIds: ["a"] });
    await assert.rejects(
      () => ai.run(p.id),
      (e) => !e.message.includes("synthetic-secret"),
    );
  }
  let resolve;
  const ai = new Insights(
    preferences,
    async () => await new Promise((r) => (resolve = r)),
  );
  const p = ai.prepare(snapshot, { flowIds: ["a"] });
  const first = ai.run(p.id);
  await assert.rejects(() => ai.run(p.id), /already running/);
  await new Promise((r) => setImmediate(r));
  resolve(
    new Response(
      JSON.stringify({
        output: [
          { type: "message", content: [{ type: "output_text", text: "Done" }] },
        ],
      }),
    ),
  );
  await first;
});
test("OpenAI-compatible provider uses chat completions and handles cancellation", async () => {
  const preferences = {
    credential: async () => ({
      ...config,
      provider: "compatible",
      baseUrl: "https://provider.example/v1",
      token: "test-placeholder",
    }),
  };
  let sent;
  const ai = new Insights(preferences, async (url, options) => {
    sent = { url, ...options };
    return new Response(
      JSON.stringify({
        choices: [{ message: { content: "Review complete." } }],
      }),
    );
  });
  const p = ai.prepare(snapshot, { flowIds: ["a"] });
  assert.equal((await ai.run(p.id)).text, "Review complete.");
  assert.equal(sent.url, "https://provider.example/v1/chat/completions");
  assert.equal(JSON.parse(sent.body).messages[0].role, "system");
  const cancel = new Insights(
    preferences,
    async (_url, options) =>
      await new Promise((_resolve, reject) =>
        options.signal.addEventListener("abort", () =>
          reject(new Error("aborted")),
        ),
      ),
  );
  const pending = cancel.run(cancel.prepare(snapshot, { flowIds: ["a"] }).id);
  await new Promise((r) => setImmediate(r));
  cancel.cancel();
  await assert.rejects(() => pending, /canceled/);
});
