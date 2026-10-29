const fs = require("node:fs/promises");
const path = require("node:path");
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const { nativeRequest } = require("../electron/firewall.cjs");
const agent = path.join(
  __dirname,
  "../native/bin",
  require("../package.json").version,
  "Watchmen.Agent.exe",
);
function run(exe, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(exe, args, {
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    child.stdout.on("data", (data) => (out += data));
    child.stderr.on("data", () => {});
    child.on("error", reject);
    child.on("close", (code) => {
      try {
        const value = JSON.parse(out);
        if (code) reject(new Error(value.error || "Probe failed."));
        else resolve(value);
      } catch (error) {
        reject(error);
      }
    });
  });
}
(async () => {
  await fs.mkdir("test-results", { recursive: true });
  const workspace = await fs.mkdtemp(
    path.join(process.cwd(), "test-results", "firewall-probes-"),
  );
  await fs.cp(path.dirname(agent), workspace, {
    recursive: true,
  });
  const allowed = path.join(workspace, "AllowedProbe.exe"),
    other = path.join(workspace, "BlockedProbe.exe");
  await fs.copyFile(agent, allowed);
  await fs.copyFile(agent, other);
  const initial = await nativeRequest(agent, { action: "list" });
  assert.equal(initial.admin, true, "Administrator access is required.");
  const previous = new Set(initial.rules.map((r) => r.id));
  const owned = [];
  const result = {
    passed: false,
    appBlock: false,
    connectionBlock: false,
    unblockRestoresAccess: false,
    osRulesSurviveHelperRestart: false,
    scopedIsolation: null,
    unrelatedRulesPreserved: false,
    cleanup: false,
  };
  const probe = () => run(other, ["--connect-probe", "1.1.1.1", "443"]);
  const waitProbe = async (connected) => {
    const deadline = Date.now() + 15000;
    let last;
    do {
      last = await probe();
      if (last.connected === connected) return true;
      await new Promise((resolve) => setTimeout(resolve, 500));
    } while (Date.now() < deadline);
    result.lastProbe = last;
    return false;
  };
  const add = async (rule) => {
    const state = await nativeRequest(agent, { action: "add", rule });
    const created = state.rules.find(
      (r) => !previous.has(r.id) && !owned.includes(r.id),
    );
    assert.ok(created);
    owned.push(created.id);
    assert.equal(
      created.enabled,
      true,
      "The created rule is not enabled: " + JSON.stringify(created),
    );
    return created;
  };
  try {
    const baseline = await probe();
    result.baseline = baseline;
    assert.equal(
      baseline.connected,
      true,
      "The controlled external probe baseline must connect: " +
        JSON.stringify(baseline),
    );
    const app = await add({
      kind: "app",
      label: "Watchmen controlled app test",
      appPath: other,
    });
    result.appBlock = await waitProbe(false);
    assert.equal(
      result.appBlock,
      true,
      "The app rule did not block the controlled probe.",
    );
    const persisted = await nativeRequest(agent, { action: "list" });
    result.osRulesSurviveHelperRestart = persisted.rules.some(
      (r) => r.id === app.id && r.enabled,
    );
    assert.equal(result.osRulesSurviveHelperRestart, true);
    await nativeRequest(agent, {
      action: "set-enabled",
      id: app.id,
      enabled: false,
    });
    assert.equal(await waitProbe(true), true);
    result.unblockRestoresAccess = true;
    const connection = await add({
      kind: "connection",
      label: "Watchmen controlled endpoint test",
      appPath: other,
      address: "1.1.1.1",
      protocol: "TCP",
      port: 443,
    });
    result.connectionBlock = await waitProbe(false);
    assert.equal(result.connectionBlock, true);
    await nativeRequest(agent, {
      action: "set-enabled",
      id: connection.id,
      enabled: false,
    });
    assert.equal(await waitProbe(true), true);
    result.scopedIsolation = await run(agent, [
      "--test-app-isolation",
      allowed,
      other,
    ]);
    assert.equal(result.scopedIsolation.passed, true);
    const final = await nativeRequest(agent, { action: "list" });
    result.unrelatedRulesPreserved = initial.rules.every((prior) =>
      final.rules.some((r) => r.id === prior.id && r.enabled === prior.enabled),
    );
    assert.equal(result.unrelatedRulesPreserved, true);
    result.passed = true;
  } finally {
    for (const id of owned) {
      await nativeRequest(agent, { action: "set-enabled", id, enabled: false });
      await nativeRequest(agent, { action: "forget", id });
    }
    const state = await nativeRequest(agent, { action: "list" });
    result.cleanup = owned.every((id) => !state.rules.some((r) => r.id === id));
    await fs.writeFile(
      "test-results/firewall-live-smoke.json",
      JSON.stringify(result, null, 2),
    );
    console.log(JSON.stringify(result, null, 2));
  }
})().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
