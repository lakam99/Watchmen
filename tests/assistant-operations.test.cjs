const { test } = require("node:test"),
  assert = require("node:assert/strict");
const {
  AssistantTools,
  definitions,
  validate,
} = require("../electron/assistant-tools.cjs");
const { Investigation } = require("../electron/assistant-investigation.cjs");
const { AppViewBridge } = require("../electron/app-view-bridge.cjs");
const { Assistant } = require("../electron/assistant.cjs");
const options = { shareIPs: false, ipLookups: false, webSearch: false };
function fixture() {
  const calls = [],
    flow = {
      id: "flow",
      pid: 10,
      app: "Browser",
      processPath: "C:\\Secret\\Browser.exe",
      remoteAddress: "10.0.0.1",
      remotePort: 443,
      protocol: "TCP",
      active: true,
    };
  const snapshot = {
    admin: true,
    flows: [flow],
    adapters: [{ id: "nic", name: "Adapter" }],
  };
  let rules = [
    {
      id: "saved",
      kind: "onlyRegion",
      label: "Canada",
      countries: ["CA"],
      allowLocalNetwork: true,
      allowUnknown: false,
      enabled: false,
      partial: false,
    },
  ];
  const state = () => ({
    rules: structuredClone(rules),
    isolationVerified: true,
    busy: false,
    job: null,
  });
  const firewall = {
    status: state,
    refresh: async () => state(),
    catalog: () => ({
      countries: [{ code: "CA", name: "Canada", region: "North America" }],
    }),
    prepare: async (input) => ({
      id: "preview",
      rule: {
        ...input,
        countries: input.countries || [],
        appPath: input.flowId ? flow.processPath : "",
      },
    }),
    apply: async () => {
      calls.push("apply");
      throw new Error("not implemented");
    },
    toggle: async (id, enabled) => {
      calls.push(["toggle", id, enabled]);
      rules.find((r) => r.id === id).enabled = enabled;
      return state();
    },
    forget: async (id) => {
      calls.push(["forget", id]);
      rules = rules.filter((r) => r.id !== id);
      return state();
    },
    cancel: () => calls.push("cancel"),
  };
  let packet = {
    id: "1",
    timestamp: 1,
    app: "Browser",
    protocol: "TCP",
    direction: "in",
    length: 30,
    source: "10.0.0.1",
    destination: "8.8.8.8",
    summary: "PRIVATE DNS NAME",
    payloadText: "secret payload",
    headers: [{ name: "secret", value: "password" }],
    hexHeaders: "secret raw",
  };
  const profile = {
    id: "profile-id",
    name: "Browser",
    path: flow.processPath,
    destinations: 1,
  };
  const anomalies = {
    list: () => ({
      alerts: [
        {
          id: "change",
          type: "new_destination",
          app_name: "Browser",
          status: "open",
        },
      ],
      counts: { open: 1 },
    }),
    explainPayload: (id, ips) => {
      assert.equal(ips, false);
      return {
        id,
        app: "Browser",
        type: "new_destination",
        evidence: { summary: "New destination" },
      };
    },
    openIds: () => ["change"],
    setStatus: (...args) => calls.push(["change", ...args]),
  };
  const history = {
    summary: () => ({
      range: "7d",
      applications: [profile],
      destinations: [{ address: "10.0.0.1", country: "Canada" }],
      daily: [],
      totals: { applications: 1 },
    }),
    detail: () => ({
      application: profile,
      endpoints: [{ address: "10.0.0.1", protocol: "TCP", port: 443 }],
    }),
    anomalies,
  };
  const operations = {
    packets: {
      status: () => ({ packets: [packet], active: false }),
      start: async (n) => calls.push(["capture", n]),
      stop: async () => calls.push("stop"),
    },
    updates: {
      status: () => ({ phase: "ready", availableVersion: "1.0.0" }),
      check: async () => {
        calls.push("check");
        return {};
      },
      download: async () => {
        calls.push("download");
        return {};
      },
    },
    showView: async (c) => calls.push(["view", c]),
    importCapture: async () => {
      calls.push("import");
      return {};
    },
    exportSession: async () => {
      calls.push("export");
      return {};
    },
    pickApplication: async (only) => {
      calls.push(["picker", only]);
      return {
        id: "picked",
        rule: {
          kind: only ? "onlyApp" : "app",
          appPath: "C:\\Chosen.exe",
          label: "Chosen",
        },
      };
    },
    restartElevated: async () => {
      calls.push("elevate");
      return true;
    },
    installUpdate: async () => calls.push("install"),
    revealApplication: async (f) => calls.push(["reveal", f.processPath]),
    openOfficial: async (t) => calls.push(t),
    historyChanged: () => calls.push("history"),
  };
  const tools = new AssistantTools({
    snapshot: () => snapshot,
    history: () => history,
    firewall,
    operations,
  });
  const execute = (n, a = {}) => tools.execute(n, a, options);
  const approve = async (task, extra = {}, ack = false) => {
    const p = await execute("propose_app_action", { task, ...extra });
    return tools.approve(p.proposalId, ack);
  };
  return {
    tools,
    execute,
    approve,
    calls,
    flow,
    snapshot,
    firewall,
    history,
    operations,
    get rules() {
      return rules;
    },
    setPacket: (p) => (packet = p),
  };
}
test("capability catalog exposes fixed app operations but no settings, paths, URLs or execution tools", async () => {
  const f = fixture(),
    catalog = await f.execute("app_capabilities");
  assert.ok(catalog.tasks.includes("import_capture"));
  for (const name of [
    "setTheme",
    "saveAI",
    "setLocations",
    "assistant_configure",
    "shell",
    "execute",
    "sql",
    "fetch_url",
  ])
    assert.ok(!definitions(options).some((d) => d.function.name === name));
  for (const [n, a] of [
    ["propose_app_action", { task: "save_settings" }],
    ["propose_app_action", { task: "import_capture", path: "C:\\Secret" }],
    ["show_view", { page: "Settings" }],
    ["show_view", { shareIPs: "true" }],
    ["show_view", { window: "120" }],
    ["propose_app_action", { task: "export_session", targetRef: "forged" }],
    ["propose_app_action", { task: "stop_capture", seconds: "10" }],
  ])
    await assert.rejects(() => f.execute(n, a));
  assert.deepEqual(f.calls, []);
});
test("full history and packet metadata remain bounded and exclude local paths, addresses and decoded content", async () => {
  const f = fixture(),
    s = await f.execute("traffic_profile"),
    d = await f.execute("profile_detail", {
      profileRef: s.applications[0].profileRef,
    }),
    c = await f.execute("connection_changes", { status: "archived" }),
    change = await f.execute("change_detail", {
      changeRef: c.changes[0].changeRef,
    }),
    p = await f.execute("packet_headers");
  const text = JSON.stringify({ s, d, c, change, p });
  for (const secret of [
    "C:\\Secret",
    "10.0.0.1",
    "PRIVATE DNS",
    "secret payload",
    "password",
    "secret raw",
  ])
    assert.ok(!text.includes(secret), secret);
  const shared = await f.tools.execute(
    "packet_headers",
    {},
    { ...options, shareIPs: true },
  );
  assert.equal(shared.packets[0].destinationPublicIP, "8.8.8.8");
  assert.ok(!JSON.stringify(shared).includes("10.0.0.1"));
  assert.equal(p.cacheable, false);
  assert.ok(p.packets[0].packetRef);
});
test("operational views resolve opaque references and never disclose local packet contents to the model", async () => {
  const f = fixture(),
    p = await f.execute("packet_headers");
  await f.execute("show_view", { targetRef: p.packets[0].packetRef });
  assert.equal(f.calls.at(-1)[1].packetId, "1");
  assert.equal(f.calls.at(-1)[1].page, "Packets");
  f.setPacket({ id: "1", timestamp: 99, summary: "new capture" });
  await assert.rejects(() =>
    f.execute("show_view", { targetRef: p.packets[0].packetRef }),
  );
  const a = await f.execute("network_status");
  await f.execute("show_view", {
    adapterRef: a.adapters[0].adapterRef,
    display: "pause",
    window: "300",
    query: "Browser",
  });
  assert.equal(f.calls.at(-1)[1].adapter, "nic");
  const c = await f.execute("inspect_connections");
  await f.execute("show_view", { targetRef: c.connections[0].connectionRef });
  assert.equal(f.calls.at(-1)[1].groupId, "TCP");
  await assert.rejects(() => f.execute("show_view", { targetRef: "invented" }));
});
test("all non-network app tasks require single-use approval and only invoke fixed service adapters", async () => {
  for (const task of [
    "start_capture",
    "stop_capture",
    "import_capture",
    "export_session",
    "restart_elevated",
    "check_updates",
    "download_update",
    "install_update",
    "open_release",
    "open_country_source",
  ]) {
    const f = fixture(),
      p = await f.execute("propose_app_action", {
        task,
        ...(task === "start_capture" ? { seconds: "20" } : {}),
      });
    assert.equal(f.calls.length, 0, task);
    const v = await f.tools.approve(p.proposalId, true);
    assert.equal(v.status, "completed", task + ": " + v.result);
    assert.equal(f.calls.length, 1, task);
    await assert.rejects(() => f.tools.approve(p.proposalId, true));
  }
});
test("packet capture requires admin while local imports and exports do not", async () => {
  const f = fixture();
  f.snapshot.admin = false;
  const p = await f.execute("propose_app_action", { task: "start_capture" });
  await assert.rejects(() => f.tools.approve(p.proposalId));
  assert.deepEqual(f.calls, []);
  assert.equal((await f.approve("import_capture")).status, "completed");
  assert.equal((await f.approve("export_session")).status, "completed");
});
test("executable selection opens a user picker and produces a second exact review without applying any policy", async () => {
  const f = fixture();
  const v = await f.approve("choose_app_only", {}, true);
  assert.equal(v.status, "completed");
  const pending = f.tools.views().filter((p) => p.status === "pending");
  assert.equal(pending.length, 1);
  assert.equal(pending[0].target.appPath, "C:\\Chosen.exe");
  assert.equal(pending[0].requiresAcknowledgement, true);
  assert.deepEqual(f.calls, [["picker", true]]);
});
test("geographic and only-app proposals require exact exceptions and broad acknowledgement, and cancelled preparation cannot create a late review", async () => {
  const f = fixture();
  await assert.rejects(() =>
    f.execute("propose_block", { scope: "onlyRegion", countries: "CA,US" }),
  );
  const p = await f.execute("propose_block", {
    scope: "onlyRegion",
    countries: "CA,US",
    localNetwork: "allow",
    unknownLocations: "block",
  });
  const v = f.tools.views()[0];
  assert.deepEqual(v.target.countries, ["CA", "US"]);
  assert.equal(v.target.allowLocalNetwork, true);
  assert.equal(v.target.allowUnknown, false);
  await assert.rejects(() => f.tools.approve(p.proposalId));
  assert.deepEqual(f.calls, []);
  f.tools.discardPending();
  let finish;
  f.firewall.prepare = () => new Promise((r) => (finish = r));
  const controller = new AbortController(),
    pending = f.tools.execute(
      "propose_block",
      { scope: "region", countries: "CA" },
      options,
      controller.signal,
    );
  controller.abort();
  await assert.rejects(() => pending);
  finish({ id: "late", rule: { kind: "region" } });
  await new Promise((r) => setImmediate(r));
  assert.ok(!f.tools.views().some((v) => v.status === "pending"));
});
test("saved-rule enable/forget are fingerprint checked and unblocking all freezes the reviewed rules", async () => {
  const f = fixture();
  let s = await f.execute("network_rules");
  const ref = s.rules[0].ruleRef;
  const p = await f.execute("propose_app_action", {
    task: "enable_rule",
    targetRef: ref,
  });
  await assert.rejects(() => f.tools.approve(p.proposalId));
  assert.equal((await f.tools.approve(p.proposalId, true)).status, "completed");
  assert.equal(f.rules[0].enabled, true);
  const all = await f.execute("propose_app_action", { task: "unblock_all" });
  f.rules.push({ id: "new", kind: "app", enabled: true, partial: false });
  assert.equal(f.tools.views().at(-1).target.reviewedRules.length, 1);
  assert.equal(
    (await f.tools.approve(all.proposalId, true)).status,
    "completed",
  );
  assert.equal(f.rules[0].enabled, false);
  assert.equal(f.rules[1].enabled, true);
  s = await f.execute("network_rules");
  const forget = await f.execute("propose_app_action", {
    task: "forget_rule",
    targetRef: s.rules[0].ruleRef,
  });
  f.rules[0].countries = ["US"];
  assert.equal(
    (await f.tools.approve(forget.proposalId, true)).status,
    "failed",
  );
  assert.equal(f.rules.length, 2);
});
test("broad rule verification cannot confuse an existing country policy with the requested policy", async () => {
  const f = fixture();
  f.firewall.apply = async () => ({
    isolationVerified: true,
    rules: [
      {
        kind: "onlyRegion",
        countries: ["US"],
        allowLocalNetwork: true,
        allowUnknown: false,
        enabled: true,
        partial: false,
      },
    ],
  });
  const p = await f.execute("propose_block", {
    scope: "onlyRegion",
    countries: "CA",
    localNetwork: "allow",
    unknownLocations: "block",
  });
  assert.equal(
    (await f.tools.approve(p.proposalId, true)).status,
    "needs_verification",
  );
});
test("change status actions use discovered group IDs, require approval, and freeze bulk group selection", async () => {
  const f = fixture(),
    c = await f.execute("connection_changes");
  for (const task of ["dismiss_change", "reopen_change"]) {
    const before = f.calls.length;
    const p = await f.execute("propose_app_action", {
      task,
      targetRef: c.changes[0].changeRef,
    });
    assert.equal(f.calls.length, before);
    assert.equal((await f.tools.approve(p.proposalId)).status, "completed");
  }
  const p = await f.execute("propose_app_action", {
    task: "dismiss_all_changes",
  });
  f.history.anomalies.openIds = () => ["change", "new"];
  assert.equal((await f.tools.approve(p.proposalId, true)).status, "completed");
  assert.ok(
    !f.calls.some(
      (c) => Array.isArray(c) && c[0] === "change" && c[1] === "new",
    ),
  );
});
test("live status/display/cancellation are never cached while reviewed action proposals are deduplicated", async () => {
  const f = fixture(),
    i = new Investigation("test", Date.now());
  for (const tool of [
    "operation_status",
    "packet_headers",
    "show_view",
    "cancel_network_task",
  ]) {
    const args = tool === "show_view" ? { page: "Packets" } : {};
    const result = await f.execute(tool, args);
    i.remember({
      status: "completed",
      tool,
      arguments: args,
      result,
      at: Date.now(),
    });
    assert.equal(i.reuse(tool, args, f.tools.views()), null);
  }
  const result = await f.execute("propose_app_action", {
    task: "import_capture",
  });
  i.remember({
    status: "completed",
    tool: "propose_app_action",
    arguments: { task: "import_capture" },
    result,
    at: Date.now(),
  });
  assert.equal(
    i.reuse("propose_app_action", { task: "import_capture" }, f.tools.views())
      .proposalId,
    result.proposalId,
  );
  assert.equal(f.tools.proposals.length, 1);
});
test("view operations wait for matching acknowledgement and are cancellable without accepting arbitrary acknowledgements", async () => {
  let command;
  const bridge = new AppViewBridge((c) => (command = c));
  const p = bridge.request({ page: "Packets" });
  assert.equal(bridge.acknowledge("forged"), false);
  assert.equal(bridge.acknowledge(command.id), true);
  await p;
  assert.equal(bridge.acknowledge(command.id), false);
  const controller = new AbortController(),
    pending = bridge.request({ page: "Overview" }, controller.signal);
  controller.abort();
  await assert.rejects(() => pending, /cancelled/);
  assert.equal(bridge.pending.size, 0);
});
test("a running approved task leaves chat available for fresh progress and cancellation tools", async () => {
  const f = fixture();
  let finish;
  f.operations.importCapture = () => new Promise((r) => (finish = r));
  const p = await f.execute("propose_app_action", { task: "import_capture" }),
    approval = f.tools.approve(p.proposalId);
  assert.equal(f.tools.actionBusy, true);
  let step = 0;
  const manager = new Assistant({
    preferences: {
      credential: async () => ({
        provider: "openrouter",
        baseUrl: "https://openrouter.ai/api/v1",
        model: "fixture",
        token: "synthetic",
      }),
    },
    settings: { get: () => options },
    snapshot: () => f.snapshot,
    history: () => f.history,
    firewall: f.firewall,
    operations: f.operations,
    fetch: async () =>
      new Response(
        JSON.stringify({
          choices: [
            {
              message:
                step++ === 0
                  ? {
                      role: "assistant",
                      tool_calls: [
                        {
                          id: "status",
                          type: "function",
                          function: {
                            name: "operation_status",
                            arguments: "{}",
                          },
                        },
                        {
                          id: "cancel",
                          type: "function",
                          function: {
                            name: "cancel_network_task",
                            arguments: "{}",
                          },
                        },
                      ],
                    }
                  : {
                      role: "assistant",
                      content: "Progress checked and cancellation requested.",
                    },
            },
          ],
        }),
      ),
  });
  manager.tools = f.tools;
  const result = await manager.send(
    "Check task progress and cancel the network task",
  );
  assert.equal(result.error, null);
  assert.ok(f.calls.includes("cancel"));
  assert.equal(f.tools.actionBusy, true);
  finish(null);
  await approval;
  assert.equal(f.tools.actionBusy, false);
});
test("later live rows and saved rules are reachable without expanding bounded tool responses", async () => {
  const f = fixture();
  for (let i = 0; i < 45; i++) {
    f.rules.push({
      id: "r" + i,
      kind: "app",
      label: "Later app",
      enabled: true,
      partial: false,
    });
    f.snapshot.flows.push({
      ...f.flow,
      id: "f" + i,
      app: "App " + i,
      processPath: `C:\\App${i}.exe`,
    });
  }
  const rules = await f.execute("network_rules");
  assert.equal(rules.rules.length, 40);
  const next = await f.execute("network_rules", { offset: rules.nextOffset });
  assert.equal(next.rules.length, 6);
  assert.equal(next.nextOffset, null);
  const apps = await f.execute("list_applications");
  assert.equal(
    (await f.execute("list_applications", { offset: apps.nextOffset }))
      .applications.length,
    16,
  );
  await assert.rejects(() => f.execute("network_rules", { offset: "-1" }));
  validate("show_view", { query: "" }, options);
  await f.execute("show_view", { query: "" });
  assert.equal(f.calls.at(-1)[1].query, "");
});
test("a reviewed explanation can be saved to a discovered change without exposing AI settings or writing before approval", async () => {
  const f = fixture();
  f.history.anomalies.saveExplanation = (...args) =>
    f.calls.push(["explanation", ...args]);
  f.operations.aiIdentity = () => ({
    provider: "openai",
    model: "fixture-model",
  });
  const c = await f.execute("connection_changes"),
    args = {
      task: "save_change_explanation",
      targetRef: c.changes[0].changeRef,
      explanation:
        "A new destination was observed; this alone does not establish a threat.",
    };
  const p = await f.execute("propose_app_action", args);
  assert.deepEqual(f.calls, []);
  const result = await f.tools.approve(p.proposalId);
  assert.equal(result.status, "completed");
  assert.equal(f.calls[0][1], "change");
  assert.equal(f.calls[0][2].provider, "openai");
  assert.equal(f.calls[0][2].text, args.explanation);
  await assert.rejects(() =>
    f.execute("propose_app_action", {
      task: "export_session",
      explanation: "ignored data",
    }),
  );
});
