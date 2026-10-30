const { test } = require("node:test");
const assert = require("node:assert/strict");
const { RowOverview, rowPayload } = require("../electron/row-overview.cjs");
const token = 'synthetic-row-secret-"quoted"' + "x".repeat(200);
const row = {
  id: "row-request-1",
  kind: "connection",
  label: "192.168.1.1 · C:\\Private\\Browser.exe",
  facts: {
    app: "Browser",
    protocol: "TCP",
    remotePort: 443,
    state: "Established",
    measured: false,
    received: null,
  },
};
const cfg = (provider) => ({
  provider,
  baseUrl:
    provider === "openai"
      ? "https://api.openai.com/v1"
      : "https://openrouter.ai/api/v1",
  model: "fixture-model",
  token,
});
const answer = (
  provider,
  text = "This is an established TCP connection commonly associated with HTTPS. Port alone does not confirm its purpose.",
) =>
  new Response(
    JSON.stringify(
      provider === "openai"
        ? {
            status: "completed",
            output: [
              { type: "message", content: [{ type: "output_text", text }] },
            ],
          }
        : { choices: [{ message: { content: text } }] },
    ),
  );
test("row payload accepts bounded table metadata and excludes labels, addresses and paths", () => {
  const payload = rowPayload({
    ...row,
    payloadText: "private packet content",
    processPath: "C:\\Private\\Browser.exe",
    facts: {
      ...row.facts,
      country: "Canada",
      networkOwner: "Example 8.8.8.8 2001:db8::42",
      app: "C:\\Program Files\\Private\\Browser.exe",
      received: 9000,
    },
  });
  const encoded = JSON.stringify(payload);
  for (const hidden of [
    "8.8.8.8",
    "192.168.1.1",
    "2001:db8",
    "Program Files",
    "Private",
    "private packet",
    "label",
  ])
    assert.ok(!encoded.includes(hidden));
  assert.equal(payload.facts.received, null);
  assert.equal(payload.facts.country, "Canada");
  assert.equal(payload.facts.app, "[path omitted]");
});
test("unsupported facts, prototype fields, oversized strings, invalid counters and ports fail before requesting a provider", async () => {
  let sent = 0;
  const manager = new RowOverview(
    {
      credential: async () => {
        sent++;
        return cfg("openai");
      },
    },
    () => {
      throw new Error("must not fetch");
    },
  );
  for (const facts of [
    { payloadText: "secret" },
    { remoteIP: "8.8.8.8" },
    { processPath: "C:\\Private" },
    { received: Infinity },
    { remotePort: 65536 },
    { observations: -1 },
    { app: "a".repeat(1001) },
    JSON.parse('{"__proto__":"bad"}'),
  ])
    await assert.rejects(
      () => manager.explain({ ...row, facts }),
      /unsupported/,
    );
  await assert.rejects(
    () => manager.explain({ ...row, kind: "shell" }),
    /supported table/,
  );
  assert.equal(sent, 0);
});
test("both providers get a succinct read-only row prompt with credentials and local context excluded", async () => {
  for (const provider of ["openai", "openrouter"]) {
    let captured;
    const manager = new RowOverview(
      { credential: async () => cfg(provider) },
      async (url, init) => {
        captured = JSON.parse(init.body);
        assert.equal(
          url,
          cfg(provider).baseUrl +
            (provider === "openai" ? "/responses" : "/chat/completions"),
        );
        assert.equal(init.headers.Authorization, "Bearer " + token);
        assert.equal(init.cache, "no-store");
        assert.equal(init.redirect, "error");
        const input =
          provider === "openai" ? captured.input : captured.messages[1].content;
        const prompt =
          provider === "openai"
            ? captured.instructions
            : captured.messages[0].content;
        assert.match(prompt, /2-3 short sentences/);
        assert.match(prompt, /cannot browse, run tools, change rules/);
        const payload = JSON.parse(input);
        assert.equal(payload.rowType, "connection");
        assert.equal(payload.facts.app, "Browser [redacted]");
        assert.ok(
          !JSON.stringify(captured).includes(
            JSON.stringify(token).slice(1, -1),
          ),
        );
        assert.ok(!JSON.stringify(captured).includes("192.168.1.1"));
        assert.ok(!JSON.stringify(captured).includes("Private"));
        if (provider === "openai") assert.equal(captured.store, false);
        else {
          assert.deepEqual(captured.tools, []);
          assert.equal(captured.tool_choice, "none");
          assert.deepEqual(captured.plugins, [{ id: "web", enabled: false }]);
        }
        return answer(provider, "Overview " + token);
      },
    );
    const result = await manager.explain({
      ...row,
      facts: { ...row.facts, app: "Browser " + token },
    });
    assert.equal(result.text, "Overview [redacted]");
    assert.ok(!JSON.stringify(result).includes(token));
    assert.equal(result.provider, provider);
  }
});
test("row cancellation is scoped to its request and stops a pending overview", async () => {
  let signal;
  const manager = new RowOverview(
    { credential: async () => cfg("openai") },
    async (_, init) => {
      signal = init.signal;
      return new Promise((_, reject) =>
        signal.addEventListener("abort", () => reject(new Error("aborted")), {
          once: true,
        }),
      );
    },
  );
  const pending = manager.explain(row);
  await new Promise(setImmediate);
  manager.cancel("another-request");
  assert.equal(signal.aborted, false);
  await assert.rejects(
    () => manager.explain({ ...row, id: "another-request" }),
    /current row overview/,
  );
  manager.cancel(row.id);
  await assert.rejects(() => pending, /canceled or timed out/);
  assert.equal(manager.controller, null);
});
test("automatic web model variants and provider errors cannot silently research or expose secrets", async () => {
  let fetches = 0;
  const manager = new RowOverview(
    {
      credential: async () => ({
        ...cfg("openrouter"),
        model: "fixture:online",
      }),
    },
    () => {
      fetches++;
    },
  );
  await assert.rejects(
    () => manager.explain(row),
    /without automatic web access/,
  );
  assert.equal(fetches, 0);
  const failing = new RowOverview(
    { credential: async () => cfg("openai") },
    async () => new Response(token, { status: 429 }),
  );
  await assert.rejects(
    () => failing.explain(row),
    (error) =>
      /rate limit/.test(error.message) && !error.message.includes(token),
  );
});
