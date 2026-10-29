const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  { randomUUID } = require("node:crypto");
const { Assistant, readJSON } = require("../electron/assistant.cjs"),
  {
    AssistantTools,
    definitions,
    sourceURL,
  } = require("../electron/assistant-tools.cjs"),
  { Firewall } = require("../electron/firewall.cjs"),
  { normalize } = require("../electron/settings-store.cjs");
const token = "synthetic-secret-" + randomUUID();
const flow = (extra = {}) => ({
  id: "observed-flow",
  app: "Example Browser",
  processPath: "C:\\Apps\\Browser.exe",
  pid: 9001,
  remoteAddress: "8.8.8.8",
  localAddress: "10.0.0.5",
  localPort: 51000,
  remotePort: 443,
  protocol: "TCP",
  active: true,
  state: "Established",
  received: 200,
  sent: 100,
  rxRate: 20,
  txRate: 10,
  ...extra,
});
const reply = (message) =>
  new Response(
    JSON.stringify({
      choices: [{ message: { role: "assistant", ...message } }],
    }),
  );
const call = (name, args = {}, id = randomUUID()) => ({
  content: null,
  tool_calls: [
    {
      id,
      type: "function",
      function: { name, arguments: JSON.stringify(args) },
    },
  ],
});
const lastTool = (body) =>
  JSON.parse(body.messages.filter((m) => m.role === "tool").at(-1).content);
function fixture({
  fetch,
  options = {},
  rules = [],
  admin = true,
  verified = true,
} = {}) {
  let now = Date.now();
  const snapshot = {
    timestamp: new Date(now).toISOString(),
    admin,
    tracing: false,
    flows: [
      flow(),
      flow({
        id: "other-binary",
        processPath: "D:\\Other\\Browser.exe",
        remoteAddress: "10.0.0.8",
      }),
    ],
    profileStatus: { available: true },
    rxRate: 1000,
    txRate: 200,
  };
  let saved = structuredClone(rules),
    permissions = {
      shareIPs: false,
      ipLookups: false,
      webSearch: false,
      ...options,
    };
  const native = [],
    requests = [];
  const state = () => ({
    rules: structuredClone(saved),
    admin,
    profiles: [],
    isolationVerified: verified,
    updatedAt: new Date(now).toISOString(),
    verificationError: verified ? null : "unavailable",
  });
  const firewall = new Firewall("unused-assistant-test", {
    snapshot: () => snapshot,
    transport: async (request) => {
      native.push(structuredClone(request));
      if (request.action === "add")
        saved.push({
          ...request.rule,
          id: randomUUID(),
          enabled: true,
          partial: false,
          createdAt: new Date(now).toISOString(),
        });
      if (request.action === "set-enabled")
        saved.find((r) => r.id === request.id).enabled = request.enabled;
      return state();
    },
  });
  const settings = {
    get: () => structuredClone(permissions),
    patch: async (_, input) =>
      (permissions = normalize("assistant", { ...permissions, ...input })),
  };
  const manager = new Assistant({
    preferences: {
      credential: async () => ({
        provider: "openrouter",
        baseUrl: "https://openrouter.ai/api/v1",
        model: "fixture/tool-model",
        token,
      }),
    },
    settings,
    snapshot: () => snapshot,
    history: () => null,
    firewall,
    clock: () => now,
    fetch: async (url, init) => {
      const body = init.body ? JSON.parse(init.body) : null;
      requests.push({ url, body, headers: init.headers });
      return fetch
        ? fetch(body, url, init)
        : reply({ content: "No tasks executed." });
    },
  });
  return {
    manager,
    snapshot,
    firewall,
    requests,
    native,
    settings,
    advance: (ms) => (now += ms),
    saved: () => saved,
  };
}
test("multi-step OpenRouter tool loop reads current targets without disclosing paths, private IPs, or credentials", async () => {
  let step = 0;
  const f = fixture({
    fetch: (body) => {
      assert.equal(body.parallel_tool_calls, false);
      assert.deepEqual(body.plugins, [{ id: "web", enabled: false }]);
      assert.ok(body.tools.every((t) => t.type === "function"));
      if (step++ === 0) return reply(call("list_applications"));
      if (step === 2) {
        const data = lastTool(body);
        assert.equal(data.applications.length, 2);
        return reply(
          call("inspect_connections", { appRef: data.applications[0].appRef }),
        );
      }
      const data = lastTool(body);
      assert.equal(data.connections.length, 1);
      assert.equal(data.connections[0].received, null);
      assert.equal(data.connections[0].publicIP, undefined);
      return reply({ content: "Observed one connection. " + token });
    },
  });
  const result = await f.manager.send("Inspect current browser traffic.");
  assert.equal(result.busy, false);
  assert.equal(result.error, null);
  assert.equal(result.trace.length, 2);
  assert.match(result.messages.at(-1).text, /\[redacted\]/);
  const sent = JSON.stringify(f.requests.map((r) => r.body));
  for (const privateValue of [
    "C:\\Apps",
    "D:\\Other",
    "10.0.0.5",
    "10.0.0.8",
    "8.8.8.8",
    token,
  ])
    assert.ok(!sent.includes(privateValue));
  assert.equal(f.native.filter((r) => r.action !== "list").length, 0);
  assert.equal(f.requests[0].headers.Authorization, "Bearer " + token);
});
async function prepareBlock(f) {
  const list = await f.manager.tools.execute(
    "list_applications",
    {},
    f.manager.options(),
  );
  return f.manager.tools.execute(
    "propose_block",
    { scope: "app", targetRef: list.applications[0].appRef },
    f.manager.options(),
  );
}
test("a block is frozen from a discovered executable and only local approval executes it once", async () => {
  const f = fixture();
  await prepareBlock(f);
  const review = f.manager.status().proposals[0];
  assert.equal(f.native.length, 0);
  assert.equal(review.target.appPath, "C:\\Apps\\Browser.exe");
  assert.equal(review.internal, undefined);
  review.target.appPath = "C:\\Injected.exe";
  const state = await f.manager.approve(review.id, false);
  assert.equal(state.proposals[0].status, "completed");
  assert.equal(f.saved()[0].appPath, "C:\\Apps\\Browser.exe");
  await assert.rejects(
    () => f.manager.approve(review.id, false),
    /not awaiting/,
  );
  assert.equal(f.native.filter((r) => r.action === "add").length, 1);
});
test("model-supplied execution names, paths, bulk scopes and unenabled tools cannot mutate rules", async () => {
  const f = fixture();
  const names = definitions(f.manager.options()).map((t) => t.function.name);
  for (const name of [
    "approve",
    "execute",
    "shell",
    "fetch_url",
    "unblock_all",
    "search_web",
    "lookup_destination",
  ])
    assert.ok(!names.includes(name));
  for (const [name, args] of [
    ["approve", {}],
    ["constructor", {}],
    ["network_status", { constructor: "unexpected" }],
    ["network_status", JSON.parse('{"__proto__":"unexpected"}')],
    ["propose_block", { scope: "onlyApp", targetRef: "invented" }],
    [
      "propose_block",
      { scope: "app", targetRef: "invented", appPath: "C:\\Injected.exe" },
    ],
    ["propose_unblock", { ruleRef: "invented" }],
    ["search_web", { query: "test" }],
  ])
    await assert.rejects(() =>
      f.manager.tools.execute(name, args, f.manager.options()),
    );
  assert.equal(f.native.length, 0);
  assert.equal(f.manager.status().proposals.length, 0);
});
test("the model can propose a block through the loop but cannot treat its approval as a tool", async () => {
  let step = 0;
  const f = fixture({
    fetch: (body) => {
      if (step++ === 0) return reply(call("list_applications"));
      if (step === 2)
        return reply(
          call("propose_block", {
            scope: "app",
            targetRef: lastTool(body).applications[0].appRef,
          }),
        );
      assert.equal(lastTool(body).status, "pending_user_approval");
      return reply({
        content:
          "The exact application is ready for local review. Nothing has been changed.",
      });
    },
  });
  const state = await f.manager.send(
    "Prepare a block for the first browser executable.",
  );
  assert.equal(state.proposals[0].status, "pending");
  assert.equal(f.native.length, 0);
  const protocol = JSON.stringify(f.requests.map((r) => r.body));
  assert.ok(!protocol.includes("Browser.exe"));
  assert.ok(!protocol.includes("previewId"));
});
test("unblock targets one existing rule, detects retargeting, and reports overlapping-rule limits", async () => {
  const rule = {
    id: "saved-id",
    kind: "connection",
    label: "Example endpoint",
    appPath: flow().processPath,
    address: "8.8.8.8",
    protocol: "TCP",
    port: 443,
    countries: [],
    enabled: true,
    createdAt: "fixed",
  };
  const f = fixture({ rules: [rule] });
  const list = await f.manager.tools.execute(
    "network_rules",
    {},
    f.manager.options(),
  );
  assert.equal(list.rules[0].publicIP, undefined);
  assert.equal(list.rules[0].appPath, undefined);
  await f.manager.tools.execute(
    "propose_unblock",
    { ruleRef: list.rules[0].ruleRef },
    f.manager.options(),
  );
  f.saved()[0].address = "1.1.1.1";
  let state = await f.manager.approve(
    f.manager.status().proposals[0].id,
    false,
  );
  assert.equal(state.proposals[0].status, "failed");
  assert.equal(f.native.filter((r) => r.action === "set-enabled").length, 0);
  const next = await f.manager.tools.execute(
    "network_rules",
    {},
    f.manager.options(),
  );
  await f.manager.tools.execute(
    "propose_unblock",
    { ruleRef: next.rules[0].ruleRef },
    f.manager.options(),
  );
  state = await f.manager.approve(
    f.manager.status().proposals.at(-1).id,
    false,
  );
  assert.equal(state.proposals.at(-1).status, "completed");
  assert.equal(f.saved()[0].enabled, false);
  assert.match(state.proposals.at(-1).result, /Other rules/);
});
test("administrator gating, review expiry, rejection, and unverified enforcement remain explicit", async () => {
  const f = fixture({ admin: false });
  await prepareBlock(f);
  await assert.rejects(
    () => f.manager.approve(f.manager.status().proposals[0].id, false),
    /administrator/,
  );
  assert.equal(f.native.length, 0);
  f.snapshot.admin = true;
  f.advance(300001);
  await assert.rejects(
    () => f.manager.approve(f.manager.status().proposals[0].id, false),
    /not awaiting/,
  );
  f.advance(-300001);
  await prepareBlock(f);
  f.manager.reject(f.manager.status().proposals.at(-1).id);
  assert.equal(f.native.length, 0);
  const u = fixture({ verified: false });
  await prepareBlock(u);
  const result = await u.manager.approve(
    u.manager.status().proposals[0].id,
    false,
  );
  assert.equal(result.proposals[0].status, "needs_verification");
  assert.match(result.proposals[0].result, /verification is unavailable/);
});
test("broad saved-rule disables require an explicit local acknowledgement", async () => {
  const f = fixture({
    rules: [
      {
        id: "region-id",
        kind: "onlyRegion",
        label: "Country-only fixture",
        appPath: "",
        address: "",
        protocol: "",
        port: 0,
        countries: ["CA", "US"],
        enabled: true,
      },
    ],
  });
  const list = await f.manager.tools.execute(
    "network_rules",
    {},
    f.manager.options(),
  );
  await f.manager.tools.execute(
    "propose_unblock",
    { ruleRef: list.rules[0].ruleRef },
    f.manager.options(),
  );
  const p = f.manager.status().proposals[0];
  await assert.rejects(() => f.manager.approve(p.id, false), /Acknowledge/);
  assert.equal(f.native.filter((r) => r.action === "set-enabled").length, 0);
  const result = await f.manager.approve(p.id, true);
  assert.equal(result.proposals[0].status, "completed");
});
test("reused flow IDs cannot select another executable or endpoint", async () => {
  const f = fixture();
  const data = await f.manager.tools.execute(
    "inspect_connections",
    {},
    f.manager.options(),
  );
  f.snapshot.flows[0].processPath = "C:\\Different.exe";
  await assert.rejects(
    () =>
      f.manager.tools.execute(
        "propose_block",
        { scope: "connection", targetRef: data.connections[0].connectionRef },
        f.manager.options(),
      ),
    /stale/,
  );
  assert.equal(f.native.length, 0);
});
test("public IP lookups use a fixed HTTPS endpoint, no AI credential, no private or documentation targets", async () => {
  const f = fixture({
    options: { ipLookups: true },
    fetch: (_, url, init) => {
      assert.ok(url.startsWith("https://ipwho.is/"));
      assert.equal(init.headers, undefined);
      assert.equal(init.redirect, "error");
      assert.equal(init.cache, "no-store");
      return new Response(
        JSON.stringify({
          success: true,
          country: "Example country",
          city: "Example city",
          connection: { org: "Example network" },
        }),
      );
    },
  });
  const c = await f.manager.tools.execute(
    "inspect_connections",
    {},
    f.manager.options(),
  );
  const result = await f.manager.tools.execute(
    "lookup_destination",
    { connectionRef: c.connections[0].connectionRef },
    f.manager.options(),
    new AbortController().signal,
  );
  assert.equal(result.publicIP, undefined);
  assert.equal(result.networkOwner, "Example network");
  await assert.rejects(
    () =>
      f.manager.tools.execute(
        "lookup_destination",
        { connectionRef: c.connections[1].connectionRef },
        f.manager.options(),
        new AbortController().signal,
      ),
    /Only public/,
  );
  assert.equal(f.requests.length, 1);
});
test("web research is opt-in, isolated from local context, cites HTTPS sources, and rejects secret/private queries", async () => {
  let step = 0;
  const f = fixture({
    options: { webSearch: true },
    fetch: (body) => {
      if (body.tools.some((t) => t.type === "openrouter:web_search")) {
        assert.equal(body.tools.length, 1);
        assert.equal(body.tools[0].parameters.max_uses, 1);
        assert.ok(!JSON.stringify(body).includes("appRef"));
        assert.ok(!JSON.stringify(body).includes("Browser.exe"));
        return reply({
          content: "QUIC commonly uses UDP.",
          annotations: [
            {
              type: "url_citation",
              url_citation: {
                url: "https://www.rfc-editor.org/rfc/rfc9000",
                title: "QUIC specification",
              },
            },
            {
              type: "url_citation",
              url_citation: { url: "file:///C:/private", title: "not allowed" },
            },
          ],
        });
      }
      if (step++ === 0)
        return reply(
          call("search_web", { query: "What transport does QUIC use?" }),
        );
      assert.equal(lastTool(body).sources.length, 1);
      return reply({ content: "The cited source describes QUIC's transport." });
    },
  });
  const state = await f.manager.send("Research QUIC using public sources.");
  assert.equal(state.error, null);
  assert.equal(state.messages.at(-1).sources.length, 1);
  for (const query of [
    "https://127.0.0.1/private",
    "Research 10.0.0.1",
    "C:\\Users\\private",
    "Bearer secret",
  ])
    await assert.rejects(
      () =>
        f.manager.tools.execute("search_web", { query }, f.manager.options()),
      /query|IP research/,
    );
  for (const url of [
    "javascript:alert(1)",
    "file:///C:/private",
    "https://localhost/a",
    "https://127.0.0.1/",
    "https://service.internal/",
    "https://user:pass@example.com",
  ])
    assert.equal(sourceURL(url), null);
});
test("changing permissions invalidates prior transcripts, targets and pending actions", async () => {
  const f = fixture({ options: { shareIPs: true } });
  await prepareBlock(f);
  const old = f.manager.status().proposals[0].id;
  await f.manager.configure({
    shareIPs: false,
    webSearch: false,
    ipLookups: false,
  });
  assert.equal(f.manager.status().proposals.length, 0);
  assert.equal(f.manager.turns.length, 0);
  await assert.rejects(() => f.manager.approve(old, false), /not awaiting/);
  assert.equal(f.native.length, 0);
  assert.throws(
    () =>
      normalize("assistant", {
        shareIPs: "true",
        ipLookups: false,
        webSearch: false,
      }),
    /permissions/,
  );
});
test("cancellation ignores late model tool calls and cannot clear a newer active turn", async () => {
  const pending = [];
  const f = fixture({
    fetch: () => new Promise((resolve) => pending.push(resolve)),
  });
  const first = f.manager.send("First request");
  await new Promise(setImmediate);
  f.manager.cancel();
  const second = f.manager.send("Second request");
  await new Promise(setImmediate);
  pending[0](
    reply(call("propose_block", { scope: "app", targetRef: "forged" })),
  );
  await first;
  assert.equal(f.manager.busy, true);
  pending[1](reply({ content: "Second response." }));
  await second;
  assert.equal(f.manager.busy, false);
  assert.equal(f.manager.status().proposals.length, 0);
  assert.equal(f.native.length, 0);
});
test("tool loops and oversized provider responses stop at bounded limits without leaking raw errors", async () => {
  const f = fixture({ fetch: () => reply(call("network_status")) });
  const result = await f.manager.send("Keep checking");
  assert.match(result.error, /six-step/);
  assert.equal(result.busy, false);
  assert.equal(f.requests.length, 6);
  await assert.rejects(
    () => readJSON(new Response("x".repeat(256001))),
    /size limit/,
  );
  const e = fixture({
    fetch: () => {
      throw new Error("network headers include " + token);
    },
  });
  const failed = await e.manager.send("Hello");
  assert.ok(!JSON.stringify(failed).includes(token));
  assert.match(failed.error, /console request failed/);
});
test("untrusted local lookup exceptions do not leak hidden addresses into the next model request", async () => {
  let step = 0;
  const f = fixture({
    options: { ipLookups: true },
    fetch: (body, url) => {
      if (url.startsWith("https://ipwho.is"))
        throw new Error("request failed for 8.8.8.8 and C:\\Private");
      if (step++ === 0) return reply(call("inspect_connections"));
      if (step === 2)
        return reply(
          call("lookup_destination", {
            connectionRef: lastTool(body).connections[0].connectionRef,
          }),
        );
      assert.ok(!JSON.stringify(body).includes("8.8.8.8"));
      assert.ok(!JSON.stringify(body).includes("Private"));
      return reply({ content: "The lookup was unavailable." });
    },
  });
  const state = await f.manager.send("Look up the first public destination.");
  assert.equal(state.error, null);
  assert.equal(state.trace.at(-1).status, "failed");
});
