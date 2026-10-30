const { execFile } = require("node:child_process");
function otherWatchmenProcesses(csv, ownPids) {
  const own = new Set(ownPids);
  return csv
    .split(/\r?\n/)
    .map((line) => /^"Watchmen\.exe","(\d+)"/i.exec(line.trim()))
    .filter(Boolean)
    .map((match) => Number(match[1]))
    .filter((pid) => !own.has(pid));
}
async function assertNoOtherInstances(ownPids, { run = execFile } = {}) {
  const output = await new Promise((resolve, reject) =>
    run(
      "tasklist.exe",
      ["/FI", "IMAGENAME eq Watchmen.exe", "/FO", "CSV", "/NH"],
      { windowsHide: true, timeout: 5000, maxBuffer: 1024 * 1024 },
      (error, stdout) =>
        error
          ? reject(
              new Error(
                "Other Watchmen instances could not be checked. Quit them from their tray icons before retrying the update.",
              ),
            )
          : resolve(stdout),
    ),
  );
  if (otherWatchmenProcesses(output, ownPids).length)
    throw new Error(
      "Quit the other Watchmen instances from their tray icons before installing the update. Their monitoring and rule tasks have been left running.",
    );
}
module.exports = { assertNoOtherInstances, otherWatchmenProcesses };
