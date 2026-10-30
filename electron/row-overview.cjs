const { randomUUID } = require("node:crypto");
const { Insights } = require("./insights.cjs");
const { researchPublic, UserError } = require("./assistant.cjs");
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
  constructor(preferences, fetch, { webSearchAllowed = () => false } = {}) {
    super(preferences, fetch);
    this.webSearchAllowed = webSearchAllowed;
    this.sources = new Set();
  }
  async explain(input) {
    return this.inspect(input, false);
  }
  async researchApp(input) {
    return this.inspect(input, true);
  }
  async inspect(input, researchOnly) {
    if (this.controller)
      throw new Error("Wait for the current row overview to finish.");
    if (typeof input?.id !== "string" || !/^[\w-]{1,80}$/.test(input.id))
      throw new Error("Invalid row overview request.");
    const payload = rowPayload(input);
    this.requestId = input.id;
    this.lastRequestId = input.id;
    this.sources.clear();
    const id = randomUUID();
    this.preview = { id, payload };
    const controller = new AbortController();
    this.controller = controller;
    const timer = setTimeout(() => controller.abort(), 90000);
    try {
      const config = await this.preferences.credential();
      if (/:online\b/i.test(config.model))
        throw new Error(
          "The row overview requires a model without automatic web access. Choose a model without :online in Settings.",
        );
      const fingerprint = (c) =>
        JSON.stringify([c.provider, c.baseUrl, c.model, c.token]);
      const assertCurrent = async () => {
        if (controller.signal.aborted)
          throw new Error("AI review canceled or timed out.");
        if (
          fingerprint(await this.preferences.credential()) !==
          fingerprint(config)
        )
          throw new Error("AI settings changed. Request a fresh overview.");
        if (controller.signal.aborted)
          throw new Error("AI review canceled or timed out.");
      };
      await assertCurrent();
      const result = researchOnly
        ? {}
        : await this.run(id, { controller, config, retainController: true });
      await assertCurrent();
      const app = researchName(
        payload.facts.app?.split(config.token).join("[redacted]"),
      );
      const supported =
        (config.provider === "openai" &&
          config.baseUrl === "https://api.openai.com/v1") ||
        (config.provider === "openrouter" &&
          config.baseUrl === "https://openrouter.ai/api/v1");
      const automatic = this.webSearchAllowed() === true;
      const research = {
        app,
        eligible: !!app,
        supported,
        status: !app ? "no_app" : !supported ? "unsupported" : "not_requested",
        sources: [],
      };
      if (app && supported && (researchOnly || automatic)) {
        try {
          await assertCurrent();
          if (!researchOnly && !this.webSearchAllowed())
            throw new Error(
              "Web research permission changed. Request a fresh overview.",
            );
          const query = `Identify the Windows application/process named ${JSON.stringify(app)}. Explain its usual purpose, publisher if supported, and typical network use. Prefer official documentation; a name match cannot verify the local executable.`;
          const found = await researchPublic(
            this.fetch,
            config,
            query,
            controller.signal,
            () => Date.now(),
            true,
          );
          await assertCurrent();
          if (!researchOnly && !this.webSearchAllowed())
            throw new Error(
              "Web research permission changed. Request a fresh overview.",
            );
          Object.assign(research, {
            status: "completed",
            text: researchText(found.answer, found.sources).slice(0, 2000),
            sources: found.sources,
            researchedAt: found.researchedAt,
          });
          for (const source of found.sources) this.sources.add(source.url);
        } catch (error) {
          await assertCurrent();
          if (!researchOnly && !this.webSearchAllowed())
            throw new Error(
              "Web research permission changed. Request a fresh overview.",
            );
          research.status = "failed";
          research.notice =
            error instanceof UserError
              ? error.message
              : "App research could not complete. Check your provider and model, or try again.";
        }
      }
      return {
        ...result,
        ...(result.text ? { text: result.text.slice(0, 1400) } : {}),
        research,
      };
    } finally {
      clearTimeout(timer);
      this.preview = null;
      if (this.controller === controller) this.controller = null;
      if (this.requestId === input.id) this.requestId = null;
    }
  }
  cancel(id) {
    if (
      id === undefined ||
      id === this.requestId ||
      id === this.lastRequestId
    ) {
      super.cancel();
      this.sources.clear();
    }
    return true;
  }
  hasSource(url) {
    return this.sources.has(url);
  }
}
function researchName(value) {
  if (typeof value !== "string") return null;
  const name = value.trim();
  if (
    !name ||
    name.length > 120 ||
    !/^[\p{L}\p{N} ._()+&'-]+$/u.test(name) ||
    /\[|\]|[a-z]:|\b(?:sk-|Bearer\b)/i.test(name) ||
    /^(?:unknown|unattributed|system|idle|n\/a|none|unresolved|any application|all applications)(?:\s|$)/i.test(
      name,
    )
  )
    return null;
  if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(name)) return null;
  return name;
}
function researchText(text, sources) {
  return text
    .replace(/cite[^]*/g, "")
    .replace(
      /\[([^\]\n]{1,200})\]\((https:\/\/[^\s]{1,2048}?)\)/g,
      (full, label, url) => {
        try {
          return sources.some((s) => s.url === new URL(url).href)
            ? label
            : full;
        } catch {
          return full;
        }
      },
    );
}
module.exports = { RowOverview, rowPayload, researchName };
