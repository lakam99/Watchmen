const fs = require("node:fs"),
  { execFileSync } = require("node:child_process");
function parse(value) {
  const match = /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(value);
  if (!match) return null;
  const parts = match.slice(1).map(Number);
  return parts.every(Number.isSafeInteger) ? parts : null;
}
function compare(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}
function nextVersion(base, tags) {
  const input = parse(base);
  if (!input) throw new Error("package.json must contain a stable version.");
  const versions = tags.map(parse).filter(Boolean).sort(compare),
    latest = versions.at(-1);
  if (!latest || compare(input, latest) > 0) return base;
  latest[2]++;
  if (!Number.isSafeInteger(latest[2]))
    throw new Error("Release version is out of range.");
  return latest.join(".");
}
function prepare() {
  const base = require("../package.json").version,
    source =
      process.env.GITHUB_SHA ||
      execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
    type = process.env.GITHUB_REF_TYPE,
    name = process.env.GITHUB_REF_NAME;
  let version,
    skip = false;
  const releases = JSON.parse(
    execFileSync(
      "gh",
      ["api", "repos/lakam99/Watchmen/releases?per_page=100"],
      { encoding: "utf8" },
    ),
  );
  if (
    releases.some(
      (r) => !r.draft && r.body?.includes(`<!-- watchmen-source:${source} -->`),
    )
  )
    skip = true;
  if (type === "tag") {
    if (name !== "v" + base || !parse(base))
      throw new Error("The stable tag must match package.json.");
    version = base;
    if (releases.some((r) => r.tag_name === name && !r.draft)) skip = true;
  } else {
    const tags = execFileSync("git", ["tag", "--list", "v*"], {
      encoding: "utf8",
    })
      .trim()
      .split(/\r?\n/);
    const pointTags = execFileSync("git", ["tag", "--points-at", "HEAD"], {
      encoding: "utf8",
    })
      .trim()
      .split(/\r?\n/);
    version = pointTags.includes("v" + base) ? base : nextVersion(base, tags);
    if (version !== base)
      execFileSync(
        process.platform === "win32" ? "npm.cmd" : "npm",
        ["version", version, "--no-git-tag-version", "--ignore-scripts"],
        { stdio: "inherit", shell: process.platform === "win32" },
      );
  }
  const output = `version=${version}\ntag=v${version}\nskip=${skip}\n`;
  if (process.env.GITHUB_OUTPUT)
    fs.appendFileSync(process.env.GITHUB_OUTPUT, output);
  console.log(output.trim());
  return { version, skip };
}
if (require.main === module)
  try {
    prepare();
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
module.exports = { nextVersion, parse };
