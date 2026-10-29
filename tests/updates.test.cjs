const { test } = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const fs = require("node:fs/promises"),
  path = require("node:path"),
  os = require("node:os");
const { Updates, updateError } = require("../electron/updates.cjs");
const {
  resolveWorkspace,
  rememberWorkspace,
} = require("../electron/workspace.cjs");
const {
  otherWatchmenProcesses,
  assertNoOtherInstances,
} = require("../electron/update-install-guard.cjs");
class Adapter extends EventEmitter {
  async checkForUpdates() {
    this.emit("checking-for-update");
    this.emit("update-available", { version: "0.8.0" });
    return {};
  }
  async downloadUpdate() {
    this.emit("download-progress", {
      percent: 51,
      transferred: 51,
      total: 100,
    });
    this.emit("update-downloaded", { version: "0.8.0" });
  }
  quitAndInstall(...args) {
    this.installed = args;
  }
}
async function fixture(t, options = {}) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "watchmen-updates-")),
    adapter = new Adapter(),
    manager = new Updates(dir, {
      adapter,
      version: "0.7.0",
      supported: true,
      ...options,
    });
  t.after(async () => {
    manager.dispose();
    await fs.rm(dir, { recursive: true, force: true });
  });
  return { dir, adapter, manager };
}
test("update settings persist without credentials and background downloads never auto-install on quit", async (t) => {
  const { dir, adapter, manager } = await fixture(t);
  await manager.init();
  await manager.configure({ autoCheck: false, autoDownload: false });
  assert.equal(adapter.autoInstallOnAppQuit, false);
  assert.equal(adapter.allowDowngrade, false);
  assert.equal(adapter.allowPrerelease, false);
  assert.equal(adapter.autoDownload, false);
  assert.deepEqual(manager.settings.get("updates"), {
    autoCheck: false,
    autoDownload: false,
  });
  const next = new Updates(dir, {
    adapter: new Adapter(),
    version: "0.7.0",
    supported: false,
  });
  t.after(() => next.dispose());
  await next.init();
  assert.equal(next.status().autoCheck, false);
  assert.equal(next.status().autoDownload, false);
  next.dispose();
});
test("available, download progress and verified readiness are separate, and active tasks prevent restart", async (t) => {
  let reason = "Wait for the rule task";
  const { adapter, manager } = await fixture(t, { blocked: () => reason });
  await manager.configure({ autoCheck: false, autoDownload: false });
  await manager.check();
  assert.equal(manager.status().phase, "available");
  assert.equal(manager.status().availableVersion, "0.8.0");
  assert.throws(() => manager.install(), /Download and verify/);
  await manager.download();
  assert.equal(manager.status().phase, "ready");
  assert.equal(manager.status().percent, 100);
  assert.throws(() => manager.install(), /rule task/);
  assert.equal(adapter.installed, undefined);
  reason = null;
  manager.install();
  assert.deepEqual(adapter.installed, [false, true]);
});
test("automatic download errors are consumed, sanitized and remain retryable", async (t) => {
  const { adapter, manager } = await fixture(t);
  adapter.checkForUpdates = async () => {
    adapter.emit("update-available", { version: "0.8.0" });
    return {
      downloadPromise: Promise.reject(
        new Error("sha512 mismatch TOKEN_SECRET"),
      ),
    };
  };
  await manager.check();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(manager.status().phase, "error");
  assert.match(manager.status().error, /verification failed/i);
  assert.ok(!JSON.stringify(manager.status()).includes("TOKEN_SECRET"));
  adapter.checkForUpdates = () => {
    throw new Error("certificate SECRET");
  };
  await manager.check();
  assert.equal(manager.checking, null);
  assert.match(manager.status().error, /certificate/);
  adapter.checkForUpdates = async () => adapter.emit("update-not-available");
  await manager.check();
  assert.equal(manager.status().phase, "current");
});
test("no published release and invalid certificate have clear static errors", () => {
  assert.match(
    updateError({ message: "404 Cannot find latest" }),
    /No Windows update/,
  );
  assert.match(
    updateError({ message: "certificate invalid bearer secret" }),
    /certificate/,
  );
  assert.equal(
    updateError({ message: "bearer secret" }).includes("secret"),
    false,
  );
});
test("concurrent checks use one request and a ready update is retained", async (t) => {
  const { adapter, manager } = await fixture(t);
  let release,
    calls = 0;
  adapter.checkForUpdates = () => {
    calls++;
    return new Promise((resolve) => (release = resolve));
  };
  const first = manager.check(),
    second = manager.check();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(calls, 1);
  release({});
  await Promise.all([first, second]);
  adapter.emit("update-downloaded", { version: "0.8.0" });
  await manager.check();
  assert.equal(calls, 1);
  assert.equal(manager.status().phase, "ready");
});
test("workspace pointer preserves portable traffic/token location across installer paths; test overrides cannot change it", async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "watchmen-workspace-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const repo = path.join(dir, "repo"),
    userData = path.join(dir, "userData"),
    installed = path.join(dir, "installed"),
    testDir = path.join(dir, "test");
  await fs.mkdir(repo, { recursive: true });
  await fs.mkdir(installed);
  await fs.mkdir(testDir);
  await fs.writeFile(path.join(repo, "package.json"), '{"name":"watchmen"}');
  const common = { packaged: true, root: repo, userData };
  assert.equal(
    await resolveWorkspace({
      ...common,
      executable: path.join(
        repo,
        "release",
        "0.7.0",
        "Watchmen-win32-x64",
        "Watchmen.exe",
      ),
    }),
    repo,
  );
  assert.equal(
    await resolveWorkspace({
      ...common,
      executable: path.join(installed, "Watchmen.exe"),
    }),
    repo,
  );
  assert.equal(
    await resolveWorkspace({
      ...common,
      executable: path.join(installed, "Watchmen.exe"),
      override: testDir,
    }),
    testDir,
  );
  assert.equal(
    JSON.parse(
      await fs.readFile(path.join(userData, "watchmen-workspace.json")),
    ).workspace,
    repo,
  );
});
test("installer guard excludes own renderer processes and refuses other instances or failed enumeration", async () => {
  const csv =
    '"Watchmen.exe","100","Console","1","50 K"\n"Watchmen.exe","101","Console","1","20 K"\n"Watchmen.exe","200","Console","1","20 K"';
  assert.deepEqual(otherWatchmenProcesses(csv, [100, 101]), [200]);
  await assert.rejects(
    assertNoOtherInstances([100, 101], {
      run: (_exe, _args, _opts, done) => done(null, csv),
    }),
    /other Watchmen windows/,
  );
  await assertNoOtherInstances([100, 101, 200], {
    run: (_exe, _args, _opts, done) => done(null, csv),
  });
  await assert.rejects(
    assertNoOtherInstances([], {
      run: (_exe, _args, _opts, done) => done(new Error("denied")),
    }),
    /could not be checked/,
  );
});

test("a failed workspace-pointer write does not stop monitoring, but strict update preservation fails", async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "watchmen-pointer-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const userData = path.join(dir, "blocked-profile");
  await fs.writeFile(userData, "fixture");
  const workspace = await resolveWorkspace({
    packaged: true,
    executable: path.join(dir, "app", "Watchmen.exe"),
    root: dir,
    userData,
  });
  assert.equal(workspace, path.join(dir, "app"));
  await assert.rejects(rememberWorkspace(workspace, userData));
});
