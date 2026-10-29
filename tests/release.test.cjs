const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  { nextVersion } = require("../scripts/prepare-release.cjs");
test("each subsequent change gets a newer stable patch unless an explicit newer version is supplied", () => {
  assert.equal(nextVersion("0.8.0", []), "0.8.0");
  assert.equal(nextVersion("0.8.0", ["v0.8.0"]), "0.8.1");
  assert.equal(
    nextVersion("0.8.0", ["v0.8.2", "v0.8.9", "v0.8.10", "v0.9.0-beta.1"]),
    "0.8.11",
  );
  assert.equal(nextVersion("0.9.0", ["v0.8.11"]), "0.9.0");
  assert.throws(() => nextVersion("bad", []));
});
