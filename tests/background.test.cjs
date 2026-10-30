const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  { EventEmitter } = require("node:events");
const { Background } = require("../electron/background.cjs");
const { AssistantTools } = require("../electron/assistant-tools.cjs"),
  { Investigation } = require("../electron/assistant-investigation.cjs");
function fixture(fail = false) {
  const app = new EventEmitter(),
    win = new EventEmitter(),
    updater = new EventEmitter(),
    calls = [];
  Object.assign(app, {
    quit: () => {
      calls.push("quit");
      app.emit("before-quit");
    },
  });
  let visible = true,
    minimized = false;
  Object.assign(win, {
    isVisible: () => visible,
    isDestroyed: () => false,
    isMinimized: () => minimized,
    hide: () => {
      visible = false;
      calls.push("hide");
    },
    show: () => {
      visible = true;
      calls.push("show");
    },
    focus: () => calls.push("focus"),
    restore: () => {
      minimized = false;
      calls.push("restore");
    },
    setSkipTaskbar: (value) => calls.push(["taskbar", value]),
  });
  class Tray extends EventEmitter {
    constructor() {
      super();
      if (fail) throw new Error("no tray");
      this.dead = false;
    }
    isDestroyed() {
      return this.dead;
    }
    destroy() {
      this.dead = true;
    }
    setContextMenu(menu) {
      this.menu = menu;
    }
    setToolTip(text) {
      this.tooltip = text;
    }
  }
  const Menu = {
    buildFromTemplate: (items) => ({
      items,
      getMenuItemById: (id) => items.find((i) => i.id === id),
    }),
  };
  const bg = new Background({
    app,
    win,
    Tray,
    Menu,
    nativeImage: { createFromPath: () => ({ isEmpty: () => false }) },
    icon: "fixture",
    updater,
    onUnavailable: () => calls.push("unavailable"),
  });
  const close = () => {
    let prevented = false;
    win.emit("close", { preventDefault: () => (prevented = true) });
    return prevented;
  };
  return {
    app,
    win,
    updater,
    calls,
    bg,
    close,
    minimize: () => (minimized = true),
  };
}
test("window close hides to a real tray controller without requesting shutdown; menu and icon restore the same window", () => {
  const f = fixture();
  f.bg.update({ timestamp: "now" });
  assert.equal(f.close(), true);
  assert.equal(f.win.isVisible(), false);
  assert.ok(!f.calls.includes("quit"));
  assert.match(f.bg.tray.tooltip, /Monitoring in background/);
  f.minimize();
  f.bg.tray.emit("click");
  assert.equal(f.win.isVisible(), true);
  assert.ok(f.calls.includes("restore"));
  assert.deepEqual(f.calls.filter(Array.isArray), [
    ["taskbar", true],
    ["taskbar", false],
  ]);
  f.bg.menu.getMenuItemById("hide-watchmen").click();
  assert.equal(f.win.isVisible(), false);
  f.bg.menu.getMenuItemById("show-watchmen").click();
  assert.equal(f.win.isVisible(), true);
});
test("explicit tray quit is single-use and app/updater/session shutdown bypass hide-on-close", () => {
  const f = fixture();
  f.close();
  f.bg.menu.getMenuItemById("quit-watchmen").click();
  f.bg.quit();
  assert.equal(f.calls.filter((c) => c === "quit").length, 1);
  assert.equal(f.close(), false);
  assert.equal(f.bg.show(), false);
  for (const [object, event] of [
    ["app", "before-quit"],
    ["updater", "before-quit-for-update"],
    ["win", "query-session-end"],
    ["win", "session-end"],
  ]) {
    const f = fixture();
    f[object].emit(event);
    assert.equal(f.close(), false, event);
  }
});
test("failed or lost tray cannot leave an inaccessible hidden process", () => {
  const f = fixture(true);
  assert.ok(f.calls.includes("unavailable"));
  assert.equal(f.close(), false);
  assert.equal(f.bg.hide(), false);
  assert.equal(f.win.isVisible(), true);
  const lost = fixture();
  lost.bg.tray.destroy();
  assert.equal(lost.close(), false);
  assert.equal(lost.bg.hide(), false);
});
test("tray teardown is idempotent and collector failure is not described as healthy monitoring", () => {
  const f = fixture();
  f.bg.update({ timestamp: "now", agentError: "unavailable" });
  assert.match(f.bg.tray.tooltip, /Collector unavailable/);
  f.bg.dispose();
  f.bg.dispose();
  assert.equal(f.bg.tray.isDestroyed(), true);
  assert.equal(f.app.listenerCount("activate"), 0);
  assert.equal(f.updater.listenerCount("before-quit-for-update"), 0);
  assert.equal(f.close(), false);
  assert.equal(f.bg.hide(), false);
});
test("AI visibility tools use only fixed display actions and never replay from the investigation cache", async () => {
  const calls = [],
    tools = new AssistantTools({
      snapshot: () => ({}),
      operations: {
        windowVisibility: (action) => {
          calls.push(action);
          return true;
        },
      },
    }),
    i = new Investigation("test", Date.now());
  for (const action of ["hide", "show"]) {
    const result = await tools.execute("window_visibility", { action }, {});
    assert.equal(result.cacheable, false);
    i.remember({
      status: "completed",
      tool: "window_visibility",
      arguments: { action },
      result,
      at: Date.now(),
    });
    assert.equal(i.reuse("window_visibility", { action }, []), null);
  }
  await assert.rejects(() =>
    tools.execute("window_visibility", { action: "quit" }, {}),
  );
  assert.deepEqual(calls, ["hide", "show"]);
});
