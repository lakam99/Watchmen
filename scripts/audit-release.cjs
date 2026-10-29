const fs = require("node:fs"),
  fsp = require("node:fs/promises"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  assert = require("node:assert/strict"),
  asar = require("@electron/asar"),
  yaml = require("js-yaml");
const hash = (buffer) =>
  crypto.createHash("sha256").update(buffer).digest("hex");
async function audit() {
  const version = require("../package.json").version,
    folder = path.resolve("release", version),
    reports = [];
  for (const target of [
    path.join(folder, "Watchmen-win32-x64"),
    path.join(folder, "installer/win-unpacked"),
  ]) {
    const archive = path.join(target, "resources/app.asar"),
      entries = asar
        .listPackage(archive)
        .map((entry) => entry.replaceAll("\\", "/"));
    const forbidden = entries.filter(
      (entry) =>
        /^\/(?:\.watchmen|\.git|\.github|test-results|scripts|tests|src)(?:\/|$)/.test(
          entry,
        ) || /\.(?:etl|pcap|pcapng|cap)$/i.test(entry),
    );
    assert.deepEqual(
      forbidden,
      [],
      "Private data or development material entered the package.",
    );
    assert.equal(
      JSON.parse(asar.extractFile(archive, "package.json")).version,
      version,
    );
    for (const name of [
      "electron/main.cjs",
      "electron/preload.cjs",
      "electron/updates.cjs",
      "electron/settings-store.cjs",
      "electron/preferences.cjs",
      "electron/ai-config.cjs",
      "electron/anomalies.cjs",
      "electron/workspace.cjs",
      "electron/update-install-guard.cjs",
      "dist/index.html",
    ]) {
      assert.equal(
        hash(asar.extractFile(archive, name)),
        hash(fs.readFileSync(name)),
        "Stale packaged source: " + name,
      );
    }
    const native = path.join(target, "resources/app.asar.unpacked/native/bin");
    assert.deepEqual(fs.readdirSync(native), [version]);
    assert.equal(
      hash(fs.readFileSync(path.join(native, version, "Watchmen.Agent.dll"))),
      hash(
        fs.readFileSync(path.join("native/bin", version, "Watchmen.Agent.dll")),
      ),
    );
    const config = yaml.load(
      fs.readFileSync(path.join(target, "resources/app-update.yml"), "utf8"),
    );
    assert.equal(config.provider, "github");
    assert.equal(config.owner, "lakam99");
    assert.equal(config.repo, "Watchmen");
    reports.push({
      target,
      entries: entries.length,
      sourceMatches: true,
      nativeMatches: true,
      privateDataExcluded: true,
    });
  }
  const metadata = yaml.load(
    fs.readFileSync(path.join(folder, "installer/latest.yml"), "utf8"),
  );
  assert.equal(metadata.version, version);
  const expectedName = `Watchmen-Setup-${version}-x64.exe`;
  assert.equal(metadata.files[0].url, expectedName);
  const installer = path.join(folder, "installer", expectedName),
    digest = crypto.createHash("sha512");
  for await (const chunk of fs.createReadStream(installer))
    digest.update(chunk);
  assert.equal(digest.digest("base64"), metadata.files[0].sha512);
  const result = {
    version,
    passed: true,
    createdAt: new Date().toISOString(),
    installerFeedMatchesBytes: true,
    packages: reports,
  };
  await fsp.mkdir("test-results", { recursive: true });
  await fsp.writeFile(
    `test-results/build-manifest-v${version}.json`,
    JSON.stringify(result, null, 2),
  );
  return result;
}
if (require.main === module)
  audit()
    .then((result) => console.log(JSON.stringify(result, null, 2)))
    .catch((error) => {
      console.error(error.message);
      process.exitCode = 1;
    });
module.exports = { audit };
