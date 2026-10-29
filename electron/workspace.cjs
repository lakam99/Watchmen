const fs = require("node:fs/promises");
const path = require("node:path");
// Remember the traffic/token directory across portable-to-installed upgrades.
// The Chromium userData directory is never moved; it owns the DPAPI key.
async function resolveWorkspace({
  packaged,
  executable,
  root,
  userData,
  override,
}) {
  const pointer = path.join(userData, "watchmen-workspace.json");
  let workspace = packaged ? path.dirname(executable) : root;
  if (override) workspace = path.resolve(override);
  else if (packaged) {
    let found = false,
      candidate = workspace;
    for (let depth = 0; depth < 5; depth++) {
      if (
        await fs
          .readFile(path.join(candidate, "package.json"), "utf8")
          .then((s) => JSON.parse(s).name === "watchmen")
          .catch(() => false)
      ) {
        workspace = candidate;
        found = true;
        break;
      }
      const parent = path.dirname(candidate);
      if (parent === candidate) break;
      candidate = parent;
    }
    if (!found)
      try {
        const saved = JSON.parse(await fs.readFile(pointer, "utf8"));
        if (
          path.isAbsolute(saved.workspace) &&
          (await fs.stat(saved.workspace)).isDirectory()
        )
          workspace = saved.workspace;
      } catch {}
  }
  // Test/development workspaces must never replace the installed app's pointer.
  if (packaged && !override)
    await rememberWorkspace(workspace, userData).catch(() => {});
  return workspace;
}
async function rememberWorkspace(workspace, userData) {
  const pointer = path.join(userData, "watchmen-workspace.json");
  await fs.mkdir(userData, { recursive: true });
  const temporary =
    pointer + "." + require("node:crypto").randomUUID() + ".tmp";
  try {
    await fs.writeFile(temporary, JSON.stringify({ workspace }), {
      mode: 0o600,
      flag: "wx",
    });
    await fs.rename(temporary, pointer);
  } finally {
    await fs.rm(temporary, { force: true }).catch(() => {});
  }
}
module.exports = { resolveWorkspace, rememberWorkspace };
