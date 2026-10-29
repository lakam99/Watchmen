const { contextBridge, ipcRenderer } = require("electron");
contextBridge.exposeInMainWorld("watchmen", {
  onSnapshot: (callback) => {
    const fn = (_, data) => callback(data);
    ipcRenderer.on("snapshot", fn);
    return () => ipcRenderer.removeListener("snapshot", fn);
  },
  assistantStatus: () => ipcRenderer.invoke("assistant-status"),
  assistantSend: (text) => ipcRenderer.invoke("assistant-send", text),
  assistantCancel: () => ipcRenderer.invoke("assistant-cancel"),
  assistantReset: () => ipcRenderer.invoke("assistant-reset"),
  assistantConfigure: (options) =>
    ipcRenderer.invoke("assistant-configure", options),
  assistantApprove: (id, acknowledged = false) =>
    ipcRenderer.invoke("assistant-approve", id, acknowledged),
  assistantReject: (id) => ipcRenderer.invoke("assistant-reject", id),
  assistantSource: (url) => ipcRenderer.invoke("assistant-source", url),
  onAssistant: (callback) => {
    const fn = (_, state) => callback(state);
    ipcRenderer.on("assistant-state", fn);
    return () => ipcRenderer.removeListener("assistant-state", fn);
  },
  updatesStatus: () => ipcRenderer.invoke("updates-status"),
  updatesCheck: () => ipcRenderer.invoke("updates-check"),
  updatesDownload: () => ipcRenderer.invoke("updates-download"),
  updatesConfigure: (input) => ipcRenderer.invoke("updates-configure", input),
  updatesInstall: () => ipcRenderer.invoke("updates-install"),
  updatesRelease: () => ipcRenderer.invoke("updates-release"),
  getStatus: () => ipcRenderer.invoke("status"),
  firewallStatus: (refresh = false) =>
    ipcRenderer.invoke("firewall-status", refresh),
  firewallCatalog: () => ipcRenderer.invoke("firewall-catalog"),
  openRuleDataSource: () => ipcRenderer.invoke("firewall-source"),
  firewallPreview: (input) => ipcRenderer.invoke("firewall-preview", input),
  firewallApply: (id) => ipcRenderer.invoke("firewall-apply", id),
  firewallToggle: (id, enabled) =>
    ipcRenderer.invoke("firewall-toggle", id, enabled),
  firewallForget: (id) => ipcRenderer.invoke("firewall-forget", id),
  firewallCancel: () => ipcRenderer.invoke("firewall-cancel"),
  firewallUnblockAll: () => ipcRenderer.invoke("firewall-unblock-all"),
  firewallPickApp: (only = false) =>
    ipcRenderer.invoke("firewall-pick-app", only),
  setLocations: (enabled) => ipcRenderer.invoke("locations", enabled),
  exportSession: () => ipcRenderer.invoke("export"),
  openPath: (pid) => ipcRenderer.invoke("open-path", pid),
  relaunchElevated: () => ipcRenderer.invoke("elevate"),
  viewSettings: () => ipcRenderer.invoke("view-settings"),
  saveViewSettings: (input) => ipcRenderer.invoke("view-settings-save", input),
  dismissAllChanges: () => ipcRenderer.invoke("alerts-dismiss-all"),
  preferences: () => ipcRenderer.invoke("preferences"),
  setTheme: (theme) => ipcRenderer.invoke("theme", theme),
  saveAI: (input) => ipcRenderer.invoke("ai-save", input),
  removeAIToken: () => ipcRenderer.invoke("ai-remove"),
  previewInsights: (request) => ipcRenderer.invoke("ai-preview", request),
  runInsights: (id) => ipcRenderer.invoke("ai-run", id),
  cancelInsights: () => ipcRenderer.invoke("ai-cancel"),
  alertsList: (options) => ipcRenderer.invoke("alerts-list", options),
  alertStatus: (id, status) => ipcRenderer.invoke("alert-status", id, status),
  previewAlert: (id, includeIPs) =>
    ipcRenderer.invoke("alert-preview", id, includeIPs),
  packetsStatus: () => ipcRenderer.invoke("packets-status"),
  packetsStart: (seconds) => ipcRenderer.invoke("packets-start", seconds),
  packetsStop: () => ipcRenderer.invoke("packets-stop"),
  packetDetail: (id) => ipcRenderer.invoke("packets-detail", id),
  packetsImport: () => ipcRenderer.invoke("packets-import"),
  trafficProfile: (options) => ipcRenderer.invoke("traffic-profile", options),
  trafficProfileApp: (options) =>
    ipcRenderer.invoke("traffic-profile-app", options),
});
