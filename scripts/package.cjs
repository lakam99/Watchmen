(async () => {
  const { packager } = await import("@electron/packager");
  const fs = require("node:fs/promises");
  const path = require("node:path");
  const version = require("../package.json").version;
  const outputs = await packager({
    dir: ".",
    out: require("node:path").join(
      "release",
      require("../package.json").version,
    ),
    name: "Watchmen",
    platform: "win32",
    arch: "x64",
    icon: "assets/watchmen.ico",
    overwrite: true,
    asar: { unpackDir: "native/bin" },
    prune: true,
    ignore: [
      /^\/release(?:\/|$)/,
      /^\/native\/Watchmen.Agent/,
      /^\/src/,
      /^\/tests/,
      /^\/test-results/,
      /^\/scripts/,
      /^\/\.git/,
      /^\/\.watchmen/,
      /\.(?:etl|pcap|pcapng|cap)$/i,
      new RegExp(
        "^/native/bin/(?!" + version.replaceAll(".", "\\.") + "(?:/|$))",
      ),
    ],
  });
  for (const output of outputs) {
    const recovery = (
      await fs.readFile("scripts/Unblock-Watchmen.ps1", "utf8")
    ).replaceAll("__WATCHMEN_VERSION__", version);
    await fs.writeFile(path.join(output, "Unblock-Watchmen.ps1"), recovery);
    await fs.copyFile(
      "scripts/Unblock-Watchmen.cmd",
      path.join(output, "Unblock-Watchmen.cmd"),
    );
  }
  console.log(outputs);
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
