const { spawnSync } = require("node:child_process");
const path = require("node:path");
const result = spawnSync(
  "dotnet",
  [
    "publish",
    "native/Watchmen.Agent",
    "-c",
    "Release",
    "-r",
    "win-x64",
    "--self-contained",
    "true",
    "-o",
    path.join("native", "bin", require("../package.json").version),
  ],
  { stdio: "inherit" },
);
if (result.error) console.error(result.error.message);
process.exitCode = result.status ?? 1;
