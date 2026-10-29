const { Regions } = require("../electron/regions.cjs");
const fs = require("node:fs/promises"),
  path = require("node:path");
(async () => {
  const regions = new Regions(path.resolve("test-results/region-dataset"), {
    clock: () => new Date("2026-10-28T12:00:00Z"),
    fetch: () => {
      throw new Error("Use the previously downloaded public dataset.");
    },
  });
  const result = { sourceMonth: "2026-10", countries: ["CA", "US"], modes: [] };
  for (const allowUnknown of [false, true]) {
    const start = Date.now(),
      prepared = await regions.prepare(["CA", "US"], {
        exclusive: true,
        allowLocalNetwork: true,
        allowUnknown,
      });
    result.modes.push({
      allowUnknown,
      allowLocalNetwork: true,
      rangeCount: prepared.rangeCount,
      nativeFilterCount: prepared.rangeCount * 2,
      prepareMs: Date.now() - start,
    });
  }
  await fs.writeFile(
    "test-results/country-only-dataset-smoke.json",
    JSON.stringify(result, null, 2),
  );
  console.log(JSON.stringify(result, null, 2));
})().catch((e) => {
  console.error(e.message);
  process.exitCode = 1;
});
