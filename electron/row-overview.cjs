const { randomUUID } = require("node:crypto");
const { Insights } = require("./insights.cjs");
const kinds = new Set([
  "application",
  "destination",
  "country",
  "protocol",
  "connection",
  "profile_app",
  "profile_destination",
  "profile_service",
  "change",
  "packet",
  "rule",
]);
const strings = new Set([
  "app",
  "protocol",
  "state",
  "scope",
  "country",
  "networkOwner",
  "ruleKind",
  "changeType",
  "severity",
  "direction",
]);
const numbers = new Set([
  "connections",
  "applications",
  "destinations",
  "services",
  "observations",
  "sessions",
  "received",
  "sent",
  "downloadRate",
  "uploadRate",
  "measuredMs",
  "remotePort",
  "localServicePort",
  "sourcePort",
  "destinationPort",
  "length",
  "capturedLength",
  "occurrences",
  "rangeCount",
  "nativeRuleCount",
]);
const booleans = new Set([
  "measured",
  "active",
  "enabled",
  "partial",
  "encrypted",
  "truncated",
]);
const safeText = (value) =>
  /[a-z]:[\\/]|\\\\|\/(?:Users|home|tmp|etc|var)\//i.test(value)
    ? "[path omitted]"
    : value
        .replace(
          /[\u0000-\u001f\u007f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g,
          " ",
        )
        .replace(
          /(?:[a-z]:[\\/]|\\\\|\/(?:Users|home|tmp|etc|var)\/)\S*/gi,
          "[path omitted]",
        )
        .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[address omitted]")
        .replace(/(?:[a-f0-9]{0,4}:){2,}[a-f0-9:.%]*/gi, "[address omitted]")
        .slice(0, 1000);
function rowPayload(input) {
  if (
    !input ||
    !kinds.has(input.kind) ||
    !input.facts ||
    typeof input.facts !== "object" ||
    Array.isArray(input.facts) ||
    Object.keys(input.facts).length > 32
  )
    throw new Error("Choose a supported table row.");
  const facts = {};
  for (const [key, value] of Object.entries(input.facts)) {
    if (strings.has(key) && typeof value === "string" && value.length <= 1000)
      facts[key] = safeText(value);
    else if (
      numbers.has(key) &&
      (value === null ||
        (typeof value === "number" &&
          Number.isFinite(value) &&
          value >= 0 &&
          value <= 1e15 &&
          (!/Port$/.test(key) || value <= 65535)))
    )
      facts[key] = value;
    else if (booleans.has(key) && typeof value === "boolean")
      facts[key] = value;
    else throw new Error("This row contains unsupported overview metadata.");
  }
  if (!Object.keys(facts).length)
    throw new Error("This row has no overview metadata.");
  if (facts.measured === false || facts.measuredMs === 0)
    for (const key of ["received", "sent", "downloadRate", "uploadRate"])
      if (Object.hasOwn(facts, key)) facts[key] = null;
  return {
    kind: "row_overview",
    rowType: input.kind,
    capturedAt: new Date().toISOString(),
    facts,
  };
}
class RowOverview extends Insights {
  async explain(input) {
    if (this.controller)
      throw new Error("Wait for the current row overview to finish.");
    if (typeof input?.id !== "string" || !/^[\w-]{1,80}$/.test(input.id))
      throw new Error("Invalid row overview request.");
    const payload = rowPayload(input);
    this.requestId = input.id;
    const id = randomUUID();
    this.preview = { id, payload };
    try {
      const result = await this.run(id);
      return { ...result, text: result.text.slice(0, 1400) };
    } finally {
      if (this.requestId === input.id) this.requestId = null;
    }
  }
  cancel(id) {
    if (id === undefined || id === this.requestId) super.cancel();
    return true;
  }
}
module.exports = { RowOverview, rowPayload };
