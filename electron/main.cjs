const {
  app,
  BrowserWindow,
  ipcMain,
  dialog,
  shell,
  net,
  safeStorage,
  nativeTheme,
} = require("electron");
const { spawn } = require("node:child_process");
const { createInterface } = require("node:readline");
const fs = require("node:fs/promises");
const path = require("node:path");
// Give concurrent/elevated instances separate disk caches while retaining the
// stable Chromium profile that owns the Windows safeStorage encryption key.
const runtimeCache = require("node:fs").mkdtempSync(
  path.join(app.getPath("temp"), "watchmen-cache-"),
);
app.commandLine.appendSwitch("disk-cache-dir", runtimeCache);
app.commandLine.appendSwitch("disable-gpu-shader-disk-cache");
const { isPublicIP } = require("./network.cjs");
const { Preferences } = require("./preferences.cjs");
const { Insights } = require("./insights.cjs");
const { RowOverview } = require("./row-overview.cjs");
const { TrafficStore } = require("./traffic-store.cjs");
const { Packets } = require("./packets.cjs");
const { Firewall } = require("./firewall.cjs");
const { Updates, releaseUrl } = require("./updates.cjs");
const { resolveWorkspace, rememberWorkspace } = require("./workspace.cjs");
const { SettingsStore } = require("./settings-store.cjs");
const { Assistant } = require("./assistant.cjs");
const { sourceURL } = require("./assistant-tools.cjs");
let assistant;
let rowOverview;
let localSettings;
let updates;
let firewall;
let packets;
let preferences,
  insights,
  trafficStore,
  profileError = null,
  profilePath;
let win,
  agent,
  latest = null,
  locationsEnabled = false,
  geo = new Map(),
  queue = [],
  inFlight = new Set(),
  agentError = null,
  geoRetryAt = 0,
  geoRequests = 0;
const root = path.join(__dirname, "..");
const locationStatus = () =>
  !locationsEnabled
    ? "Off"
    : geoRetryAt > Date.now()
      ? "Provider rate limit · retry later"
      : geoRequests >= 1000
        ? "Session lookup limit reached"
        : `${[...geo.values()].filter((g) => g.country !== "Lookup unavailable").length} IPs resolved · ${queue.length} queued`;
const current = () => ({
  ...latest,
  agentError,
  locationsEnabled,
  locationStatus: locationStatus(),
  locations: locationsEnabled ? Object.fromEntries(geo) : {},
  alertCount: (() => {
    try {
      return trafficStore?.anomalies.openCount() || 0;
    } catch {
      return 0;
    }
  })(),
  profileStatus: {
    available: !!trafficStore,
    databasePath: profilePath || "",
    recording: !!trafficStore?.owner,
    error: profileError,
  },
});
const send = () => {
  if (win && !win.isDestroyed()) win.webContents.send("snapshot", current());
};
function collectorPath() {
  return app.isPackaged
    ? path.join(
        process.resourcesPath,
        "app.asar.unpacked",
        "native",
        "bin",
        require("../package.json").version,
        "Watchmen.Agent.exe",
      )
    : path.join(
        root,
        "native",
        "bin",
        require("../package.json").version,
        "Watchmen.Agent.exe",
      );
}
function startAgent() {
  const agentPath = collectorPath();
  agent = spawn(agentPath, [], {
    windowsHide: true,
    stdio: ["pipe", "pipe", "pipe"],
  });
  createInterface({ input: agent.stdout }).on("line", (line) => {
    try {
      latest = JSON.parse(line);
    } catch {
      agentError = "The local collector returned an unreadable snapshot.";
      send();
      return;
    }
    agentError = null;
    if (trafficStore) {
      try {
        trafficStore.ingest(latest);
        profileError = null;
      } catch {
        profileError =
          "Traffic history could not be updated. Check the database location and available disk space.";
      }
    }
    if (locationsEnabled)
      for (const f of latest.flows)
        if (
          isPublicIP(f.remoteAddress) &&
          !geo.has(f.remoteAddress) &&
          !inFlight.has(f.remoteAddress) &&
          queue.length < 500
        ) {
          inFlight.add(f.remoteAddress);
          queue.push(f.remoteAddress);
        }
    send();
  });
  agent.stderr.on("data", (data) => {
    agentError = data.toString().trim().slice(0, 500);
    send();
  });
  agent.on("error", () => {
    agentError =
      "Collector not found. Run npm run agent:build, then restart Watchmen.";
    send();
  });
  agent.on("exit", () => {
    agentError = "The collector stopped. Restart Watchmen to reconnect.";
    send();
  });
}
const geoTimer = setInterval(async () => {
  if (
    !locationsEnabled ||
    !queue.length ||
    geoRetryAt > Date.now() ||
    geoRequests >= 1000
  )
    return;
  const ip = queue.shift();
  try {
    geoRequests++;
    const response = await net.fetch(
      "https://ipwho.is/" + encodeURIComponent(ip),
      { signal: AbortSignal.timeout(5000) },
    );
    if (response.status === 429) {
      geoRetryAt =
        Date.now() +
        Math.max(60, Number(response.headers.get("retry-after")) || 86400) *
          1000;
      queue.unshift(ip);
      return;
    }
    if (!response.ok) throw new Error("Lookup unavailable");
    const g = await response.json();
    geo.set(
      ip,
      g.success
        ? {
            country: g.country,
            code: g.country_code,
            city: g.city,
            org: g.connection?.org || g.connection?.isp || "",
            latitude: g.latitude,
            longitude: g.longitude,
          }
        : { country: "Lookup unavailable", code: "", city: "", org: "" },
    );
    try {
      trafficStore?.saveLocation(ip, geo.get(ip));
    } catch {
      profileError = "A cached IP location could not be saved.";
    }
  } catch {
    geo.set(ip, { country: "Lookup unavailable", code: "", city: "", org: "" });
  } finally {
    inFlight.delete(ip);
    send();
  }
}, 1100);
geoTimer.unref();
function assertSender(event) {
  if (event.sender !== win?.webContents) throw new Error("Untrusted sender");
}
ipcMain.handle("status", (event) => {
  assertSender(event);
  return current();
});
const safeHandle = (name, handler) =>
  ipcMain.handle(name, async (event, ...args) => {
    assertSender(event);
    try {
      return { ok: true, value: await handler(...args) };
    } catch (error) {
      return {
        ok: false,
        error: error?.message || "The operation could not be completed.",
      };
    }
  });
safeHandle("updates-status", () => updates.status());
safeHandle("updates-check", () => updates.check());
safeHandle("updates-download", () => updates.download());
safeHandle("updates-configure", (input) => updates.configure(input));
async function installUpdate() {
  await require("./update-install-guard.cjs").assertNoOtherInstances([
    process.pid,
    ...app.getAppMetrics().map((metric) => metric.pid),
  ]);
  try {
    await rememberWorkspace(
      path.dirname(preferences.dir),
      app.getPath("userData"),
    );
  } catch {
    throw new Error(
      "The traffic data directory could not be preserved for the updated app. Check its permissions before retrying; installation has not started.",
    );
  }
  return updates.install();
}
safeHandle("updates-install", installUpdate);
safeHandle("updates-release", () => shell.openExternal(releaseUrl));
safeHandle("preferences", () => preferences.status());
safeHandle("view-settings", () => localSettings.get("monitor"));
safeHandle("view-settings-save", (input) =>
  localSettings.patch("monitor", input),
);
safeHandle("firewall-status", (refresh) =>
  refresh === true ? firewall.refresh() : firewall.status(),
);
safeHandle("firewall-catalog", () => firewall.catalog());
safeHandle("firewall-source", async () => {
  await shell.openExternal("https://db-ip.com/db/lite.php");
  return true;
});
safeHandle("firewall-preview", (input) => firewall.prepare(input));
safeHandle("firewall-apply", (id) => firewall.apply(id));
safeHandle("firewall-toggle", (id, enabled) => firewall.toggle(id, enabled));
safeHandle("firewall-forget", (id) => firewall.forget(id));
safeHandle("firewall-cancel", () => firewall.cancel());
safeHandle("firewall-unblock-all", () => firewall.unblockAll());
async function pickApplication(only) {
  const result = await dialog.showOpenDialog(win, {
    title:
      only === true
        ? "Choose the only app with network access"
        : "Choose an app to block",
    properties: ["openFile"],
    filters: [{ name: "Windows executable", extensions: ["exe"] }],
  });
  if (result.canceled) return null;
  return firewall.prepareExecutable(
    result.filePaths[0],
    path.basename(result.filePaths[0]),
    only === true,
  );
}
safeHandle("firewall-pick-app", pickApplication);
safeHandle("theme", async (theme) => {
  const status = await preferences.setTheme(theme);
  nativeTheme.themeSource = theme;
  return status;
});
safeHandle("ai-save", (input) => {
  rowOverview?.cancel();
  assistant?.reset();
  return preferences.saveAI(input);
});
safeHandle("ai-remove", () => {
  rowOverview?.cancel();
  assistant?.reset();
  return preferences.removeToken();
});
safeHandle("assistant-status", () => assistant.status());
safeHandle("row-overview", (input) => rowOverview.explain(input));
safeHandle("row-overview-cancel", (id) => rowOverview.cancel(id));
safeHandle("assistant-send", (text) => assistant.send(text));
safeHandle("assistant-raise-limit", (id) => assistant.raiseLimit(id));
safeHandle("assistant-checkpoint", (id) => assistant.summarizeAndContinue(id));
safeHandle("assistant-cancel", () => assistant.cancel());
safeHandle("assistant-reset", () => assistant.reset());
safeHandle("assistant-configure", (options) => assistant.configure(options));
safeHandle("assistant-approve", (id, acknowledged) =>
  assistant.approve(id, acknowledged),
);
safeHandle("assistant-reject", (id) => assistant.reject(id));
safeHandle("assistant-source", (url) => {
  const safe = sourceURL(url);
  if (!safe || !assistant.hasSource(safe))
    throw new Error(
      "This source is not available in the current research session.",
    );
  return shell.openExternal(safe);
});
safeHandle("ai-preview", (request) => {
  let profileBaseline = [];
  if (trafficStore && Array.isArray(request?.flowIds)) {
    const ids = new Set(request.flowIds);
    try {
      profileBaseline = trafficStore.baseline(
        (latest?.flows || []).filter((f) => ids.has(f.id)),
      );
    } catch {
      profileError = "Saved application summaries could not be read.";
    }
  }
  return insights.prepare(
    {
      ...latest,
      locations: locationsEnabled ? Object.fromEntries(geo) : {},
      profileBaseline,
    },
    request,
  );
});
safeHandle("traffic-profile", (options) => {
  if (!trafficStore)
    throw new Error(
      profileError || "The local traffic database is unavailable.",
    );
  return trafficStore.summary(options);
});
safeHandle("traffic-profile-app", (options) => {
  if (!trafficStore)
    throw new Error(
      profileError || "The local traffic database is unavailable.",
    );
  return trafficStore.detail(options);
});
safeHandle("ai-run", async (id) => {
  const reply = await insights.run(id);
  if (reply.alertId)
    trafficStore?.anomalies.saveExplanation(reply.alertId, reply);
  return reply;
});
safeHandle("alerts-list", (options) => {
  if (!trafficStore)
    throw new Error(profileError || "Traffic history is unavailable.");
  return trafficStore.anomalies.list(options);
});
safeHandle("alert-status", (id, status) => {
  if (!trafficStore) throw new Error("Traffic history is unavailable.");
  const result = trafficStore.anomalies.setStatus(id, status);
  send();
  return result;
});
safeHandle("alerts-dismiss-all", () => {
  if (!trafficStore) throw new Error("Traffic history is unavailable.");
  const count = trafficStore.anomalies.dismissAll();
  send();
  return count;
});
safeHandle("alert-preview", (id, includeIPs) => {
  if (!trafficStore) throw new Error("Traffic history is unavailable.");
  return insights.prepareChange(
    trafficStore.anomalies.explainPayload(id, includeIPs === true),
  );
});
safeHandle("packets-status", () => packets.status());
safeHandle("packets-start", (seconds) => packets.start(seconds));
safeHandle("packets-stop", () => packets.stop());
safeHandle("packets-detail", (id) => packets.detail(id));
async function importCapture() {
  const { canceled, filePaths } = await dialog.showOpenDialog(win, {
    title: "Open a local packet capture",
    properties: ["openFile"],
    filters: [
      { name: "Packet captures", extensions: ["pcap", "pcapng", "cap"] },
    ],
  });
  if (canceled) return null;
  return packets.importFile(filePaths[0]);
}
safeHandle("packets-import", importCapture);
safeHandle("ai-cancel", () => {
  insights.cancel();
  return true;
});
ipcMain.handle("locations", async (event, value) => {
  assertSender(event);
  await localSettings.patch("monitor", { locationsEnabled: value === true });
  locationsEnabled = value === true;
  if (locationsEnabled && trafficStore) {
    try {
      geo = new Map([
        ...Object.entries(trafficStore.cachedLocations()),
        ...geo,
      ]);
    } catch {
      profileError = "Cached IP locations could not be read.";
    }
  }
  if (!locationsEnabled) {
    queue = [];
    inFlight.clear();
  }
  send();
  return locationsEnabled;
});
async function exportSession() {
  if (!latest) return { error: "No traffic snapshot available yet." };
  const { filePath, canceled } = await dialog.showSaveDialog(win, {
    defaultPath:
      "watchmen-cache-" +
      new Date().toISOString().replace(/[:.]/g, "-") +
      ".json",
    filters: [{ name: "Traffic session (JSON)", extensions: ["json"] }],
  });
  if (canceled) return { canceled: true };
  await fs.writeFile(
    filePath,
    JSON.stringify(
      {
        ...latest,
        locations: locationsEnabled ? Object.fromEntries(geo) : {},
        exportedAt: new Date().toISOString(),
      },
      null,
      2,
    ),
  );
  return { ok: true };
}
ipcMain.handle("export", async (event) => {
  assertSender(event);
  return exportSession();
});
ipcMain.handle("open-path", async (event, pid) => {
  assertSender(event);
  const flow = latest?.flows.find((f) => f.pid === pid);
  if (flow?.processPath) {
    shell.showItemInFolder(flow.processPath);
    return true;
  }
  return false;
});
async function restartElevated() {
  if (
    firewall?.busy ||
    packets?.status()?.active ||
    packets?.status()?.processing
  )
    throw new Error(
      "Finish or cancel the network-rule task and stop packet capture before restarting.",
    );
  const quote = (s) => "'" + s.replace(/'/g, "''") + "'";
  const args = app.isPackaged
    ? ""
    : " -ArgumentList " + quote('"' + root + '"');
  const ps = spawn(
    "powershell.exe",
    [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      `try { Start-Process -FilePath ${quote(process.execPath)}${args} -Verb RunAs -ErrorAction Stop; exit 0 } catch { exit 1 }`,
    ],
    { windowsHide: true },
  );
  return await new Promise((resolve) => {
    ps.on("error", () => resolve(false));
    ps.on("exit", (code) => {
      resolve(code === 0);
      if (code === 0) app.quit();
    });
  });
}
ipcMain.handle("elevate", async (event) => {
  assertSender(event);
  return restartElevated();
});
const viewBridge = new (require("./app-view-bridge.cjs").AppViewBridge)(
  (command) => {
    if (!win || win.isDestroyed()) throw new Error("Monitor unavailable.");
    win.webContents.send("app-operation", command);
  },
);
safeHandle("app-operation-ack", (id, error) =>
  viewBridge.acknowledge(id, error),
);
app.whenReady().then(async () => {
  const workspace = await resolveWorkspace({
    packaged: app.isPackaged,
    executable: process.execPath,
    root,
    userData: app.getPath("userData"),
    override: process.env.WATCHMEN_WORKSPACE_DIR,
  });
  localSettings = new SettingsStore(path.join(workspace, ".watchmen"));
  preferences = new Preferences(
    path.join(workspace, ".watchmen"),
    safeStorage,
    localSettings,
  );
  firewall = new Firewall(path.join(workspace, ".watchmen"), {
    agentPath: collectorPath(),
    snapshot: () => latest,
    fetch: (url, options) => net.fetch(url, options),
  });
  firewall.refresh();
  packets = new Packets(path.join(workspace, ".watchmen", "packet-captures"), {
    snapshot: () => latest,
    agentPath: collectorPath(),
  });
  profilePath = path.join(workspace, ".watchmen", "traffic.sqlite");
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      trafficStore = new TrafficStore(profilePath);
      break;
    } catch (error) {
      if (attempt < 2 && [5, 6, 8].includes(error.errcode)) {
        await new Promise((resolve) =>
          setTimeout(resolve, 150 * (attempt + 1)),
        );
        continue;
      }
      profileError =
        "The local traffic database could not be opened. Check its permissions or use a compatible Watchmen version. Existing data has been preserved.";
      break;
    }
  }
  await preferences.init();
  locationsEnabled = localSettings.get("monitor").locationsEnabled;
  if (locationsEnabled && trafficStore)
    geo = new Map(Object.entries(trafficStore.cachedLocations()));
  const { autoUpdater } = require("electron-updater");
  updates = new Updates(path.join(workspace, ".watchmen"), {
    adapter: autoUpdater,
    settings: localSettings,
    version: app.getVersion(),
    supported: app.isPackaged && process.platform === "win32",
    blocked: () =>
      firewall?.busy
        ? "Wait for the current network-rule task to finish before restarting."
        : packets?.status()?.active || packets?.status()?.processing
          ? "Stop the packet capture before restarting."
          : rowOverview?.controller
            ? "Close the AI row overview before restarting."
            : assistant?.busy
              ? "Stop the AI console response before restarting."
              : null,
  });
  await updates.init();
  nativeTheme.themeSource = preferences.value.theme;
  insights = new Insights(preferences, (url, options) =>
    net.fetch(url, options),
  );
  rowOverview = new RowOverview(preferences, (url, options) =>
    net.fetch(url, options),
  );
  assistant = new Assistant({
    preferences,
    settings: localSettings,
    snapshot: current,
    history: () => trafficStore,
    firewall,
    operations: {
      packets,
      updates,
      showView: (command, signal) => viewBridge.request(command, signal),
      importCapture,
      exportSession,
      pickApplication,
      restartElevated,
      installUpdate,
      revealApplication: (flow) => shell.showItemInFolder(flow.processPath),
      historyChanged: () => send(),
      aiIdentity: () => {
        const { provider, model } = preferences.status().ai;
        return { provider, model };
      },
      openOfficial: (task) =>
        shell.openExternal(
          task === "open_release"
            ? releaseUrl
            : "https://db-ip.com/db/lite.php",
        ),
    },
    fetch: (url, options) => net.fetch(url, options),
    changed: (state) => {
      if (win && !win.isDestroyed())
        win.webContents.send("assistant-state", state);
    },
  });
  const savedWindow = localSettings.get("window");
  win = new BrowserWindow({
    width: savedWindow.width,
    height: savedWindow.height,
    minWidth: 1000,
    minHeight: 720,
    title: "Watchmen",
    icon: path.join(root, "assets", "watchmen.png"),
    backgroundColor: nativeTheme.shouldUseDarkColors ? "#14151e" : "#f5f6fa",
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  if (savedWindow.maximized) win.maximize();
  let boundsTimer;
  const saveBounds = () => {
    if (win?.isDestroyed()) return;
    const b = win.getNormalBounds();
    localSettings
      .patch("window", {
        width: Math.max(1000, Math.min(8192, b.width)),
        height: Math.max(720, Math.min(8192, b.height)),
        maximized: win.isMaximized(),
      })
      .catch(() => {});
  };
  for (const event of ["resize", "maximize", "unmaximize"])
    win.on(event, () => {
      clearTimeout(boundsTimer);
      boundsTimer = setTimeout(saveBounds, 300);
    });
  win.on("close", () => {
    clearTimeout(boundsTimer);
    saveBounds();
  });
  win.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  win.webContents.on("will-navigate", (event) => event.preventDefault());
  win.webContents.session.setPermissionRequestHandler(
    (_web, _permission, callback) => callback(false),
  );
  win.loadFile(path.join(root, "dist", "index.html"));
  startAgent();
  const policyTimer = setInterval(() => firewall.refresh(), 30000);
  policyTimer.unref();
});
let shuttingDown = false;
let quitFinishing = false;
async function finishQuit() {
  if (quitFinishing) return;
  quitFinishing = true;
  try {
    await packets?.shutdown();
  } catch {}
  closeHistory();
  localSettings?.close();
  if (
    path.dirname(runtimeCache) === path.resolve(app.getPath("temp")) &&
    path.basename(runtimeCache).startsWith("watchmen-cache-")
  )
    await fs.rm(runtimeCache, { recursive: true, force: true }).catch(() => {});
  app.exit();
}
function closeHistory() {
  if (!trafficStore || trafficStore.closed) return;
  try {
    if (latest) trafficStore.ingest(latest, { force: true });
  } catch {}
  try {
    trafficStore.close();
  } catch {}
}
app.on("window-all-closed", () => app.quit());
app.on("before-quit", (event) => {
  assistant?.cancel();
  insights?.cancel();
  rowOverview?.cancel();
  updates?.dispose();
  if (shuttingDown) return;
  if (!agent || agent.exitCode !== null) {
    event.preventDefault();
    finishQuit();
    return;
  }
  event.preventDefault();
  shuttingDown = true;
  const timer = setTimeout(() => {
    agent.kill();
    finishQuit();
  }, 4000);
  agent.once("exit", () => {
    clearTimeout(timer);
    finishQuit();
  });
  agent.stdin.end();
});
