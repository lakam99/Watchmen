const { SettingsStore } = require("./settings-store.cjs");
const repository = "lakam99/Watchmen";
const releaseUrl = "https://github.com/" + repository + "/releases";
function updateError(error) {
  const code = String(error?.code || "");
  const message = String(error?.message || "");
  if (
    /NO_PUBLISHED_VERSIONS|LATEST_VERSION_NOT_FOUND/.test(code) ||
    /404|No published versions|Unable to find latest version|No releases/.test(
      message,
    )
  )
    return "No Windows update has been published yet. Check again after the next GitHub release.";
  if (/sha512|checksum|signature|digest/i.test(code + message))
    return "Update verification failed. The downloaded file was not installed.";
  if (/certificate|CERT_|SSL_/i.test(code + message))
    return "The release server certificate could not be verified. Check your network certificate settings.";
  return "The update could not be checked or downloaded. Check your connection and try again.";
}
class Updates {
  constructor(
    directory,
    {
      adapter,
      version,
      supported,
      blocked = () => null,
      clock = () => new Date(),
      settings = null,
    },
  ) {
    this.adapter = adapter;
    this.blocked = blocked;
    this.clock = clock;
    this.settings = settings || new SettingsStore(directory);
    this.ownsSettings = !settings;
    this.filename = this.settings.path;
    this.state = {
      currentVersion: version,
      availableVersion: null,
      phase: "idle",
      supported,
      autoCheck: true,
      autoDownload: true,
      percent: 0,
      transferred: 0,
      total: 0,
      bytesPerSecond: 0,
      checkedAt: null,
      error: null,
      message: supported
        ? "Updates come from GitHub Releases."
        : "Install a packaged Windows build to use updates.",
      repository,
      releaseUrl,
    };
    this.checking = null;
    this.downloading = null;
    this.timer = null;
    this.startTimer = null;
    adapter.autoInstallOnAppQuit = false;
    adapter.autoDownload = true;
    adapter.allowPrerelease = false;
    adapter.allowDowngrade = false;
    adapter.disableDifferentialDownload = true;
    adapter.logger = null;
    adapter.on("checking-for-update", () =>
      this.patch({
        phase: "checking",
        error: null,
        message: "Checking GitHub Releases...",
      }),
    );
    adapter.on("update-available", (info) =>
      this.patch({
        phase: this.state.autoDownload ? "downloading" : "available",
        availableVersion: info.version,
        error: null,
        message: "A newer Windows release is available.",
      }),
    );
    adapter.on("update-not-available", () =>
      this.patch({
        phase: "current",
        availableVersion: null,
        error: null,
        message: "You are using the latest published version.",
      }),
    );
    adapter.on("download-progress", (p) =>
      this.patch({
        phase: "downloading",
        percent: Math.max(0, Math.min(100, Number(p.percent) || 0)),
        transferred: Number(p.transferred) || 0,
        total: Number(p.total) || 0,
        bytesPerSecond: Number(p.bytesPerSecond) || 0,
        message: "Downloading update in the background...",
      }),
    );
    adapter.on("update-downloaded", (info) =>
      this.patch({
        phase: "ready",
        availableVersion: info.version,
        percent: 100,
        error: null,
        message: "Update downloaded and verified. Restart when you are ready.",
      }),
    );
    adapter.on("error", (error) => this.failed(error));
  }
  patch(value) {
    Object.assign(this.state, value);
    return this.status();
  }
  status() {
    return { ...this.state, installBlocked: this.blocked() };
  }
  failed(error) {
    return this.patch({
      phase: "error",
      error: updateError(error),
      message: updateError(error),
    });
  }
  async init() {
    await this.settings.init();
    Object.assign(this.state, this.settings.get("updates"));
    if (this.settings.error) this.state.error = this.settings.error;
    this.adapter.autoDownload = this.state.autoDownload;
    if (this.state.supported) {
      this.startTimer = setTimeout(() => {
        if (this.state.autoCheck) this.check().catch(() => {});
      }, 10000);
      this.startTimer.unref?.();
      this.timer = setInterval(
        () => {
          if (this.state.autoCheck) this.check().catch(() => {});
        },
        6 * 60 * 60 * 1000,
      );
      this.timer.unref?.();
    }
    return this.status();
  }
  async configure(input) {
    if (
      !input ||
      typeof input.autoCheck !== "boolean" ||
      typeof input.autoDownload !== "boolean"
    )
      throw new Error("Choose valid update preferences.");
    await this.settings.patch("updates", {
      autoCheck: input.autoCheck,
      autoDownload: input.autoDownload,
    });
    this.adapter.autoDownload = input.autoDownload;
    return this.patch({
      autoCheck: input.autoCheck,
      autoDownload: input.autoDownload,
    });
  }
  async check() {
    if (!this.state.supported) throw new Error(this.state.message);
    if (this.checking) return this.checking;
    if (["downloading", "ready", "installing"].includes(this.state.phase))
      return this.status();
    this.patch({ phase: "checking", error: null });
    this.checking = (async () => {
      try {
        const result = await Promise.resolve().then(() =>
          this.adapter.checkForUpdates(),
        );
        result?.downloadPromise?.catch((error) => this.failed(error));
        this.state.checkedAt = this.clock().toISOString();
      } catch (error) {
        this.failed(error);
      } finally {
        this.checking = null;
      }
      return this.status();
    })();
    return this.checking;
  }
  async download() {
    if (!this.state.supported || this.state.phase !== "available")
      throw new Error("Check for an available update first.");
    if (this.downloading) return this.downloading;
    this.patch({
      phase: "downloading",
      error: null,
      percent: 0,
      transferred: 0,
      total: 0,
      message: "Downloading update in the background...",
    });
    this.downloading = (async () => {
      try {
        await Promise.resolve().then(() => this.adapter.downloadUpdate());
      } catch (error) {
        this.failed(error);
      } finally {
        this.downloading = null;
      }
      return this.status();
    })();
    return this.downloading;
  }
  install() {
    if (!this.state.supported || this.state.phase !== "ready")
      throw new Error("Download and verify an update before installing it.");
    const reason = this.blocked();
    if (reason) throw new Error(reason);
    this.patch({
      phase: "installing",
      error: null,
      message: "Installing update and restarting Watchmen...",
    });
    try {
      this.adapter.quitAndInstall(false, true);
    } catch (error) {
      this.failed(error);
      throw new Error(
        "The update installer could not start. Try again from Settings.",
      );
    }
    return this.status();
  }
  dispose() {
    clearTimeout(this.startTimer);
    clearInterval(this.timer);
    if (this.ownsSettings) this.settings.close();
  }
}
module.exports = { Updates, updateError, repository, releaseUrl };
