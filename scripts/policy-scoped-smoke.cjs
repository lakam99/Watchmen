// Real WFP enforcement in the native test sublayer, loopback and one private port only.
const fs = require("node:fs/promises"),
  path = require("node:path"),
  assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
(async () => {
  const version = require("../package.json").version,
    source = path.resolve("native/bin", version),
    folder = await fs.mkdtemp(path.resolve("test-results/policy-scoped-"));
  await fs.cp(source, folder, { recursive: true });
  const agent = path.join(folder, "Watchmen.Agent.exe"),
    allowed = path.join(folder, "AllowedProbe.exe"),
    other = path.join(folder, "OtherProbe.exe");
  await fs.copyFile(agent, allowed);
  await fs.copyFile(agent, other);
  const result = await new Promise((resolve, reject) => {
    const child = spawn(agent, ["--test-app-isolation", allowed, other], {
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    child.stdout.on("data", (data) => (output += data));
    child.stderr.on("data", () => {});
    child.on("error", reject);
    child.on("close", () => {
      try {
        resolve(JSON.parse(output));
      } catch (e) {
        reject(e);
      }
    });
  });
  await fs.writeFile(
    "test-results/policy-scoped-smoke-v" + version + ".json",
    JSON.stringify(result, null, 2),
  );
  console.log(JSON.stringify(result, null, 2));
  assert.equal(result.passed, true);
  assert.equal(result.countryOnlyBlocksOutside, true);
  assert.equal(result.countryOnlyAllowsSelected, true);
})().catch((e) => {
  console.error(e.message);
  process.exitCode = 1;
});
