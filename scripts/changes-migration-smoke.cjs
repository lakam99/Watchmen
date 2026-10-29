const fs = require("node:fs/promises"),
  path = require("node:path"),
  assert = require("node:assert/strict"),
  { DatabaseSync, backup } = require("node:sqlite"),
  { TrafficStore } = require("../electron/traffic-store.cjs");
(async () => {
  await fs.mkdir("test-results", { recursive: true });
  const folder = await fs.mkdtemp(
      path.resolve("test-results/changes-migration-"),
    ),
    source = new DatabaseSync(path.resolve(".watchmen/traffic.sqlite"), {
      readOnly: true,
    }),
    destination = path.join(folder, "traffic.sqlite");
  let before;
  try {
    before = {
      alerts: source
        .prepare("SELECT COUNT(*) count FROM alerts WHERE status='open'")
        .get().count,
      historyRecords: source.prepare("SELECT COUNT(*) count FROM alerts").get()
        .count,
      applications: source
        .prepare("SELECT COUNT(*) count FROM applications")
        .get().count,
      edges: source.prepare("SELECT COUNT(*) count FROM edges").get().count,
    };
    await backup(source, destination);
  } finally {
    source.close();
  }
  const store = new TrafficStore(destination);
  try {
    const after = {
      openGroups: store.anomalies.openCount(),
      applications: store.q("SELECT COUNT(*) count FROM applications").get()
        .count,
      edges: store.q("SELECT COUNT(*) count FROM edges").get().count,
      historyRecords: store.q("SELECT COUNT(*) count FROM alerts").get().count,
    };
    assert.equal(after.applications, before.applications);
    assert.equal(after.edges, before.edges);
    assert.equal(after.historyRecords, before.historyRecords);
    assert.ok(after.openGroups < before.alerts);
    const result = {
      passed: true,
      sourceOpenedReadOnly: true,
      migrationAppliedToCopyOnly: true,
      before,
      after,
    };
    await fs.writeFile(
      "test-results/changes-migration-smoke.json",
      JSON.stringify(result, null, 2),
    );
    console.log(JSON.stringify(result, null, 2));
  } finally {
    store.close();
  }
})().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
