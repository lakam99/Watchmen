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
  constructor(
    preferences,
    fetch,
    { webSearchAllowed = () => false, cache = null } = {},
  ) {
    super(preferences, fetch);
    this.webSearchAllowed = webSearchAllowed;
    this.cache = cache;
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
    if (input.refresh !== undefined && typeof input.refresh !== "boolean")
      throw new Error("Invalid research refresh request.");
    if (input.refresh && !researchOnly)
      throw new Error("Use the app research refresh action.");
    const refresh = input.refresh === true;
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
      const app = researchName(
        payload.facts.app?.split(config.token).join("[redacted]"),
      );
      const supported =
        (config.provider === "openai" &&
          config.baseUrl === "https://api.openai.com/v1") ||
        (config.provider === "openrouter" &&
          config.baseUrl === "https://openrouter.ai/api/v1");
      const automatic = this.webSearchAllowed() === true;
      const cached = app ? this.cache?.get(app, config) : null;
      const research = {
        app,
        eligible: !!app,
        supported,
        status: !app ? "no_app" : !supported ? "unsupported" : "not_requested",
        sources: [],
        ...(cached || {}),
      };
      let saveResearch = false;
      // The cached public app description is independent of the live row data.
      let result = {};
      if (!researchOnly) {
        try {
          result = await this.run(id, {
            controller,
            config,
            retainController: true,
          });
        } catch (error) {
          await assertCurrent();
          if (!cached) throw error;
          result = {
            text: "The live row explanation is unavailable. Saved app research is shown below.",
            overviewNotice: error.message,
            model: config.model,
            provider: config.provider,
            capturedAt: payload.capturedAt,
            generatedAt: new Date().toISOString(),
          };
        }
      }
      await assertCurrent();
      if (
        app &&
        supported &&
        (researchOnly || automatic) &&
        (!cached || refresh)
      ) {
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
          const explanation = researchText(found.answer, found.sources)
            .trim()
            .slice(0, 2000);
          if (!explanation)
            throw new UserError(
              "Web research returned no usable explanation. The previous research has been kept, if available.",
            );
          Object.assign(research, {
            status: "completed",
            text: explanation,
            app,
            sources: found.sources,
            researchedAt: found.researchedAt,
            provider: config.provider,
            model: config.model,
            cached: false,
          });
          delete research.cacheSavedAt;
          saveResearch = true;
        } catch (error) {
          await assertCurrent();
          if (!researchOnly && !this.webSearchAllowed())
            throw new Error(
              "Web research permission changed. Request a fresh overview.",
            );
          research.status = cached ? "completed" : "failed";
          research.notice =
            error instanceof UserError
              ? error.message
              : "App research could not complete. Check your provider and model, or try again.";
          if (cached)
            research.notice +=
              " Showing the previously saved research; its collection date is unchanged.";
        }
      }
      if (refresh && cached && !supported)
        research.notice =
          "Use OpenAI or OpenRouter with its official endpoint to refresh. Showing the previously saved research.";
      await assertCurrent();
      if (saveResearch) {
        if (!researchOnly && !this.webSearchAllowed())
          throw new Error(
            "Web research permission changed. Request a fresh overview.",
          );
        const saved = this.cache?.put(app, research, config);
        if (this.cache && !saved)
          research.cacheNotice =
            "The research could not be saved to the local database. It is available for this session only.";
      }
      if (research.status === "completed")
        for (const source of research.sources) this.sources.add(source.url);
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
