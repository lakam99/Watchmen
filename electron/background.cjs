// Keep the existing window and collectors alive; only an explicit quit ends them.
class Background {
  constructor({
    app,
    win,
    Tray,
    Menu,
    nativeImage,
    icon,
    updater,
    onUnavailable = () => {},
  }) {
    Object.assign(this, { app, win, updater });
    this.quitting = false;
    this.disposed = false;
    this.onQuit = () => {
      this.quitting = true;
    };
    this.onClose = (event) => {
      if (this.quitting || !this.available()) return;
      event.preventDefault();
      this.hide();
    };
    this.onSessionEnd = () => {
      this.quitting = true;
    };
    this.onActivate = () => this.show();
    try {
      const image = nativeImage.createFromPath(icon);
      if (image.isEmpty()) throw new Error("Missing tray icon.");
      this.tray = new Tray(image);
      this.menu = Menu.buildFromTemplate([
        {
          label: "Show Watchmen",
          id: "show-watchmen",
          click: () => this.show(),
        },
        { label: "Hide window", id: "hide-watchmen", click: () => this.hide() },
        { type: "separator" },
        {
          label: "Quit Watchmen",
          id: "quit-watchmen",
          click: () => this.quit(),
        },
      ]);
      this.tray.setContextMenu(this.menu);
      this.tray.on("click", () => this.show());
      this.tray.on("double-click", () => this.show());
      this.update();
    } catch {
      this.tray?.destroy();
      this.tray = null;
      onUnavailable();
    }
    app.on("before-quit", this.onQuit);
    app.on("activate", this.onActivate);
    updater?.on("before-quit-for-update", this.onQuit);
    win.on("close", this.onClose);
    win.on("query-session-end", this.onSessionEnd);
    win.on("session-end", this.onSessionEnd);
  }
  available() {
    return !!this.tray && !this.tray.isDestroyed() && !this.disposed;
  }
  hide() {
    if (this.quitting || !this.available() || this.win.isDestroyed())
      return false;
    this.win.hide();
    this.win.setSkipTaskbar(true);
    this.update();
    return true;
  }
  show() {
    if (this.quitting || this.disposed || this.win.isDestroyed()) return false;
    this.win.setSkipTaskbar(false);
    if (this.win.isMinimized()) this.win.restore();
    this.win.show();
    this.win.focus();
    this.update();
    return true;
  }
  update(snapshot) {
    if (!this.available()) return;
    if (snapshot) this.snapshot = snapshot;
    const s = this.snapshot,
      visible = !this.win.isDestroyed() && this.win.isVisible();
    const state = !s?.timestamp
      ? "Starting monitor"
      : s.agentError
        ? "Collector unavailable"
        : "Monitoring";
    const suffix = visible ? "" : " in background";
    this.tray.setToolTip(`Watchmen — ${state}${suffix}`);
    this.menu.getMenuItemById("hide-watchmen").enabled = visible;
  }
  quit() {
    if (this.quitting || this.disposed) return;
    this.quitting = true;
    this.app.quit();
  }
  dispose() {
    if (this.disposed) return;
    this.disposed = true;
    this.quitting = true;
    this.win.removeListener("close", this.onClose);
    this.win.removeListener("query-session-end", this.onSessionEnd);
    this.win.removeListener("session-end", this.onSessionEnd);
    this.app.removeListener("before-quit", this.onQuit);
    this.app.removeListener("activate", this.onActivate);
    this.updater?.removeListener("before-quit-for-update", this.onQuit);
    if (this.tray && !this.tray.isDestroyed()) this.tray.destroy();
  }
}
module.exports = { Background };
