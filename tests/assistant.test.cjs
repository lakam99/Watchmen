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
const openAIReply = (output, status = "completed") =>
  new Response(JSON.stringify({ status, output }));
const openAIText = (text, annotations = []) => ({
  type: "message",
  id: "msg_" + randomUUID(),
  role: "assistant",
  status: "completed",
  content: [{ type: "output_text", text, annotations }],
});
const openAICall = (name, args = {}, call_id = "call_" + randomUUID()) => ({
  type: "function_call",
  id: "fc_" + randomUUID(),
  call_id,
  name,
  arguments: JSON.stringify(args),
  status: "completed",
});
function fixture({
  fetch,
  options = {},
  rules = [],
  admin = true,
  verified = true,
  partial = false,
  provider = "openrouter",
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
          partial,
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
  const credentials = {
    provider,
    baseUrl:
      provider === "openai"
        ? "https://api.openai.com/v1"
        : "https://openrouter.ai/api/v1",
    model: "fixture/tool-model",
    token,
  };
  const manager = new Assistant({
    preferences: { credential: async () => structuredClone(credentials) },
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
    credentials,
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
  assert.match(result.proposals[0].result, /not confirmed/);
  const p = fixture({ partial: true });
  await prepareBlock(p);
  const partialResult = await p.manager.approve(
    p.manager.status().proposals[0].id,
    false,
  );
  assert.equal(partialResult.proposals[0].status, "needs_verification");
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

test("permission revocation by another instance cannot resend previously shared context", async () => {
  const f = fixture({
    options: { shareIPs: true },
    fetch: (body) => {
      const lastUser = body.messages
        .filter((m) => m.role === "user")
        .at(-1).content;
      if (
        lastUser === "Inspect the initial connections" &&
        !body.messages.some((m) => m.role === "tool")
      )
        return reply(call("inspect_connections"));
      return reply({ content: "Current response." });
    },
  });
  await f.manager.send("Inspect the initial connections");
  assert.ok(JSON.stringify(f.requests.at(-1).body).includes("8.8.8.8"));
  await f.settings.patch("assistant", { shareIPs: false });
  await f.manager.send("A new request after revocation");
  assert.ok(!JSON.stringify(f.requests.at(-1).body).includes("8.8.8.8"));
  const other = fixture({ options: { shareIPs: true } });
  await prepareBlock(other);
  const old = other.manager.status().proposals[0].id;
  await other.settings.patch("assistant", { shareIPs: false });
  await assert.rejects(
    () => other.manager.approve(old, false),
    /Permissions changed/,
  );
  assert.equal(other.native.length, 0);
});

test("credential changes cannot reuse the previous account's context or action reviews", async () => {
  const f = fixture();
  await f.manager.send("Private context from the first account");
  await prepareBlock(f);
  const previous = f.manager.status().proposals[0].id;
  f.credentials.token += "-rotated";
  await assert.rejects(
    () => f.manager.approve(previous, false),
    /credentials changed/i,
  );
  assert.equal(f.native.length, 0);
  await f.manager.send("Request under the replacement account");
  assert.ok(
    !JSON.stringify(f.requests.at(-1).body).includes(
      "Private context from the first account",
    ),
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

test("OpenAI Responses replays call IDs and encrypted reasoning, and scoped block/unblock still require approval", async () => {
  const reasoning = {
    type: "reasoning",
    id: "rs_fixture",
    summary: [],
    encrypted_content: "encrypted-reasoning-fixture",
  };
  const f = fixture({
    provider: "openai",
    fetch: (body, url, init) => {
      assert.equal(url, "https://api.openai.com/v1/responses");
      assert.equal(init.cache, "no-store");
      assert.equal(init.redirect, "error");
      assert.equal(body.store, false);
      assert.equal(body.previous_response_id, undefined);
      assert.equal(body.plugins, undefined);
      assert.equal(body.provider, undefined);
      assert.ok(
        body.tools.every(
          (t) =>
            t.type === "function" &&
            t.strict === false &&
            t.parameters.additionalProperties === false,
        ),
      );
      assert.equal(
        body.tools.some((t) => t.name === "search_web"),
        false,
      );
      const userIndex = body.input.findLastIndex((i) => i.role === "user");
      const prompt = body.input[userIndex].content;
      const outputs = body.input
        .slice(userIndex + 1)
        .filter((i) => i.type === "function_call_output");
      for (const output of outputs)
        assert.ok(
          body.input.some(
            (i) => i.type === "function_call" && i.call_id === output.call_id,
          ),
        );
      const last = outputs.length ? JSON.parse(outputs.at(-1).output) : null;
      if (/unblock/.test(prompt)) {
        if (!last) return openAIReply([openAICall("network_rules")]);
        if (last.rules)
          return openAIReply([
            openAICall("propose_unblock", { ruleRef: last.rules[0].ruleRef }),
          ]);
        return openAIReply([openAIText("Unblock is awaiting your approval.")]);
      }
      if (!last)
        return openAIReply([reasoning, openAICall("list_applications")]);
      assert.ok(
        body.input.some(
          (i) =>
            i.type === "reasoning" &&
            i.encrypted_content === reasoning.encrypted_content,
        ),
      );
      if (last.applications)
        return openAIReply([
          openAICall("propose_block", {
            scope: "app",
            targetRef: last.applications[0].appRef,
          }),
        ]);
      return openAIReply([
        openAIText("Block is awaiting your approval. " + token),
      ]);
    },
  });
  let result = await f.manager.send("Prepare a block");
  assert.equal(result.error, null);
  assert.equal(f.native.length, 0);
  assert.equal(result.proposals[0].target.appPath, "C:\\Apps\\Browser.exe");
  assert.match(result.messages.at(-1).text, /\[redacted\]/);
  result = await f.manager.approve(result.proposals[0].id, false);
  assert.equal(result.proposals[0].status, "completed");
  assert.equal(f.saved()[0].enabled, true);
  result = await f.manager.send("Prepare an unblock");
  assert.equal(result.error, null);
  assert.equal(f.saved()[0].enabled, true);
  const pending = result.proposals.find((p) => p.status === "pending");
  result = await f.manager.approve(pending.id, false);
  assert.equal(
    result.proposals.find((p) => p.id === pending.id).status,
    "completed",
  );
  assert.equal(f.saved()[0].enabled, false);
  const bodies = JSON.stringify(f.requests.map((r) => r.body));
  for (const secret of [token, "C:\\Apps", "10.0.0.5", "8.8.8.8"])
    assert.ok(!bodies.includes(secret));
  assert.ok(
    !JSON.stringify(f.manager.status()).includes("encrypted-reasoning-fixture"),
  );
});

test("OpenAI research uses a separate opt-in Responses search and validated cited sources", async () => {
  const f = fixture({
    provider: "openai",
    options: { webSearch: true },
    fetch: (body, url) => {
      assert.equal(url, "https://api.openai.com/v1/responses");
      if (body.tools.some((t) => t.type === "web_search")) {
        assert.equal(body.tools.length, 1);
        assert.equal(body.tools[0].external_web_access, true);
        assert.equal(body.max_tool_calls, 1);
        assert.equal(body.tool_choice, "required");
        assert.equal(body.input.length, 2);
        const sent = JSON.stringify(body);
        for (const privateValue of [
          "list_applications",
          "hostActionEvents",
          "PRIVATE_CHAT_MARKER",
          token,
        ])
          assert.ok(!sent.includes(privateValue));
        return openAIReply([
          {
            type: "web_search_call",
            id: "ws_fixture",
            status: "completed",
            action: { type: "search", query: "QUIC transport specification" },
          },
          openAIText("QUIC is specified in RFC 9000.", [
            {
              type: "url_citation",
              url: "https://www.rfc-editor.org/rfc/rfc9000",
              title: "QUIC",
              start_index: 0,
              end_index: 30,
            },
            {
              type: "url_citation",
              url: "https://127.0.0.1/private",
              title: "Invalid",
              start_index: 0,
              end_index: 5,
            },
          ]),
        ]);
      }
      if (!body.input.some((i) => i.type === "function_call_output"))
        return openAIReply([
          openAICall("search_web", { query: "QUIC transport specification" }),
        ]);
      return openAIReply([
        openAIText("The cited specification describes QUIC."),
      ]);
    },
  });
  const result = await f.manager.send("PRIVATE_CHAT_MARKER Research QUIC.");
  assert.equal(result.error, null);
  assert.equal(result.trace[0].status, "completed");
  assert.deepEqual(result.messages.at(-1).sources, [
    { url: "https://www.rfc-editor.org/rfc/rfc9000", title: "QUIC" },
  ]);
  assert.equal(f.native.length, 0);
});

test("OpenAI incomplete/refused/malformed or unauthorized built-in tool responses cannot execute local tasks", async () => {
  const cases = [
    () => openAIReply([openAICall("list_applications")], "incomplete"),
    () => openAIReply([{ type: "computer_call", call_id: "forged" }]),
    () =>
      openAIReply([
        openAIText(""),
        {
          type: "message",
          role: "assistant",
          content: [{ type: "refusal", refusal: token }],
        },
      ]),
    () =>
      openAIReply([
        openAICall("network_status", {}, "duplicate"),
        openAICall("network_status", {}, "duplicate"),
      ]),
    () =>
      openAIReply([
        {
          type: "function_call",
          call_id: "invalid",
          name: "network_status",
          arguments: {},
        },
      ]),
    () =>
      new Response(JSON.stringify({ error: { message: token } }), {
        status: 429,
      }),
  ];
  for (const fetch of cases) {
    const f = fixture({ provider: "openai", fetch });
    const result = await f.manager.send("Inspect traffic");
    assert.ok(result.error);
    assert.equal(result.proposals.length, 0);
    assert.equal(f.native.length, 0);
    assert.ok(!JSON.stringify(result).includes(token));
  }
});

test("OpenAI research without a completed search is not presented as a live finding", async () => {
  const f = fixture({
    provider: "openai",
    options: { webSearch: true },
    fetch: (body) => {
      if (body.tools.some((t) => t.type === "web_search"))
        return openAIReply([
          openAIText("Invented live finding", [
            {
              type: "url_citation",
              url: "https://example.com",
              title: "Example",
            },
          ]),
        ]);
      if (!body.input.some((i) => i.type === "function_call_output"))
        return openAIReply([
          openAICall("search_web", { query: "QUIC reference" }),
        ]);
      const output = JSON.parse(
        body.input.filter((i) => i.type === "function_call_output").at(-1)
          .output,
      );
      assert.ok(output.error);
      return openAIReply([openAIText("No live finding was established.")]);
    },
  });
  const result = await f.manager.send("Research QUIC");
  assert.equal(result.error, null);
  assert.equal(result.trace[0].status, "failed");
  assert.deepEqual(result.messages.at(-1).sources, []);
});

test("switching from OpenRouter to OpenAI clears previous provider context and reviews", async () => {
  const f = fixture({
    fetch: (_, url) =>
      url.endsWith("/responses")
        ? openAIReply([openAIText("Fresh OpenAI session")])
        : reply({ content: "Previous provider context" }),
  });
  await f.manager.send("PRIVATE_OLD_PROVIDER_CONTEXT");
  await prepareBlock(f);
  const id = f.manager.status().proposals[0].id;
  f.credentials.provider = "openai";
  f.credentials.baseUrl = "https://api.openai.com/v1";
  await assert.rejects(
    () => f.manager.approve(id, false),
    /credentials changed/,
  );
  const result = await f.manager.send("New provider message");
  assert.equal(result.error, null);
  assert.equal(f.requests.at(-1).url, "https://api.openai.com/v1/responses");
  assert.ok(
    !JSON.stringify(f.requests.at(-1).body).includes(
      "PRIVATE_OLD_PROVIDER_CONTEXT",
    ),
  );
  assert.equal(result.proposals.length, 0);
  assert.equal(f.native.length, 0);
});

test("OpenAI cancellation ignores late Responses tool calls", async () => {
  let resolve;
  const f = fixture({
    provider: "openai",
    fetch: () =>
      new Promise((r) => {
        resolve = r;
      }),
  });
  const pending = f.manager.send("Inspect current apps");
  await new Promise(setImmediate);
  f.manager.cancel();
  resolve(openAIReply([openAICall("list_applications")]));
  const result = await pending;
  assert.equal(result.busy, false);
  assert.equal(result.trace.length, 0);
  assert.equal(f.native.length, 0);
});
