const fs = require("node:fs"),
  fsp = require("node:fs/promises"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  { execFileSync } = require("node:child_process");
(async () => {
  const version = require("../package.json").version;
  if (!/^\d+\.\d+\.\d+$/.test(version))
    throw new Error("Release packaging requires a stable version.");
  await require("./audit-release.cjs").audit();
  const folder = path.resolve("release", version),
    app = path.join(folder, "Watchmen-win32-x64"),
    zip = path.join(folder, `Watchmen-${version}-win32-x64.zip`);
  execFileSync(
    "powershell.exe",
    [
      "-NoProfile",
      "-NonInteractive",
      "-File",
      path.resolve("scripts/release-zip.ps1"),
      "-ApplicationFolder",
      app,
      "-Destination",
      zip,
    ],
    { windowsHide: true, stdio: "inherit" },
  );
  const assets = [
    zip,
    path.join(folder, "installer", `Watchmen-Setup-${version}-x64.exe`),
    path.join(folder, "installer/latest.yml"),
  ];
  const lines = [];
  for (const file of assets) {
    const hash = crypto.createHash("sha256");
    for await (const chunk of fs.createReadStream(file)) hash.update(chunk);
    lines.push(hash.digest("hex") + "  " + path.basename(file));
  }
  await fsp.writeFile(
    path.join(folder, "SHA256SUMS.txt"),
    lines.join("\n") + "\n",
  );
  console.log(
    "Release ZIP, installer feed and SHA256SUMS are ready in " + folder,
  );
})().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
