const path = require("node:path");
const version = require("./package.json").version;
const electronDist = path.join(__dirname, "node_modules", "electron", "dist");
module.exports = {
  appId: "com.watchmen.networkmonitor",
  productName: "Watchmen",
  // Recent Electron npm packages may contain no downloaded runtime on a clean
  // runner. Builder then downloads the exact locked Electron version itself.
  electronVersion: require("electron/package.json").version,
  ...(require("node:fs").existsSync(path.join(electronDist, "electron.exe"))
    ? { electronDist }
    : {}),
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
