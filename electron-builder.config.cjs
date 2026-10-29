const path = require("node:path");
const version = require("./package.json").version;
module.exports = {
  appId: "com.watchmen.networkmonitor",
  productName: "Watchmen",
  electronDist: "node_modules/electron/dist",
  directories: { output: path.join("release", version, "installer") },
  files: ["electron/**/*", "dist/**/*", "assets/**/*", "package.json"],
  extraResources: [
    {
      from: path.join("native", "bin", version),
      to: path.join("app.asar.unpacked", "native", "bin", version),
    },
  ],
  extraFiles: [
    {
      from: path.join(
        "release",
        version,
        "Watchmen-win32-x64",
        "Unblock-Watchmen.ps1",
      ),
      to: "Unblock-Watchmen.ps1",
    },
    { from: "scripts/Unblock-Watchmen.cmd", to: "Unblock-Watchmen.cmd" },
  ],
  win: {
    target: [{ target: "nsis", arch: ["x64"] }],
    icon: "assets/watchmen.ico",
    artifactName: "Watchmen-Setup-${version}-x64.${ext}",
  },
  nsis: {
    oneClick: false,
    allowToChangeInstallationDirectory: true,
    perMachine: false,
    allowElevation: false,
    createDesktopShortcut: true,
    createStartMenuShortcut: true,
    deleteAppDataOnUninstall: false,
    differentialPackage: false,
  },
  publish: [
    {
      provider: "github",
      owner: "lakam99",
      repo: "Watchmen",
      releaseType: "release",
    },
  ],
  asar: true,
  npmRebuild: false,
};
