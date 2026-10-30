import { useState } from "react";
import {
  Sparkles,
  Shield,
  KeyRound,
  X,
  ArrowRight,
  LoaderCircle,
  Trash2,
} from "lucide-react";
import type { Flow } from "./model";
export type AIConfig = {
  provider: "openai" | "openrouter" | "compatible";
  baseUrl: string;
  model: string;
};
// Curated text/tool models; IDs verified against the official catalogs.
// https://developers.openai.com/api/docs/models
// https://openrouter.ai/api/v1/models
const openAIModels = [
  ["gpt-6.1-sol", "GPT-6.1 Sol"],
  ["gpt-6.1-terra", "GPT-6.1 Terra"],
  ["gpt-6-astra", "GPT-6 Astra"],
  ["gpt-6-luna", "GPT-6 Luna"],
  ["gpt-4.1", "GPT-4.1"],
  ["gpt-4.1-mini", "GPT-4.1 mini"],
  ["gpt-4.1-nano", "GPT-4.1 nano"],
];
const modelChoices = (provider: AIConfig["provider"]) =>
  provider === "compatible"
    ? []
    : openAIModels.map(([id, name]) => ({
        id: provider === "openrouter" ? `openai/${id}` : id,
        name,
      }));
export type PreferencesStatus = {
  theme: "system" | "light" | "dark";
  ai: AIConfig;
  hasToken: boolean;
  credentialError: string | null;
  storageAvailable: boolean;
  storagePath: string;
  error: string | null;
};
export type Result<T> = { ok: true; value: T } | { ok: false; error: string };
export type Preview = { id: string; payload: Record<string, unknown> };
export type Insight = {
  text: string;
  model: string;
  provider: string;
  generatedAt: string;
  capturedAt: string;
  selectedConnections: number;
  sampledConnections: number;
};
export function AISettings({
  preferences,
  update,
  notify,
}: {
  preferences: PreferencesStatus | null;
  update: (p: PreferencesStatus) => void;
  notify: (s: string) => void;
}) {
  const [config, setConfig] = useState<AIConfig>(
      preferences?.ai || {
        provider: "openrouter",
        baseUrl: "https://openrouter.ai/api/v1",
        model: "openai/gpt-4.1-mini",
      },
    ),
    [token, setToken] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const [customModel, setCustomModel] = useState(
    () => !modelChoices(config.provider).some((m) => m.id === config.model),
  );
  const choices = modelChoices(config.provider);
  const save = async () => {
    if (!window.watchmen) return;
    setBusy(true);
    setError("");
    try {
      const r = await window.watchmen.saveAI({ ...config, token });
      if (r.ok) {
        setToken("");
        update(r.value);
        notify("AI settings saved. Your token is encrypted on this computer.");
      } else setError(r.error);
    } catch {
      setError("Could not save AI settings.");
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    if (!window.watchmen) return;
    setBusy(true);
    try {
      const r = await window.watchmen.removeAIToken();
      if (r.ok) {
        setToken("");
        update(r.value);
        notify("Saved AI token removed.");
      } else setError(r.error);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="ai-settings">
      <div className="section-title">
        <Sparkles size={17} />
        <strong>AI insights</strong>
        <span className="badge">
          {preferences?.hasToken ? "Token saved" : "Not configured"}
        </span>
      </div>
      <p>
        Bring your own API token. Reviews run only when you request them and may
        incur provider charges.
      </p>
      <div className="settings-fields">
        <label>
          Provider
          <select
            aria-label="AI provider"
            value={config.provider}
            onChange={(e) => {
              const provider = e.target.value as AIConfig["provider"];
              setConfig({
                provider,
                baseUrl:
                  provider === "openai"
                    ? "https://api.openai.com/v1"
                    : provider === "openrouter"
                      ? "https://openrouter.ai/api/v1"
                      : config.baseUrl,
                model:
                  provider === "openai"
                    ? "gpt-4.1-mini"
                    : provider === "openrouter"
                      ? "openai/gpt-4.1-mini"
                      : config.model,
              });
              setCustomModel(provider === "compatible");
              setToken("");
            }}
          >
            <option value="openrouter">OpenRouter</option>
            <option value="openai">OpenAI</option>
            <option value="compatible">OpenAI-compatible (HTTPS)</option>
          </select>
        </label>
        <label>
          Model
          <select
            aria-label="AI model"
            value={customModel ? "__custom" : config.model}
            onChange={(e) => {
              const custom = e.target.value === "__custom";
              setCustomModel(custom);
              if (!custom) setConfig({ ...config, model: e.target.value });
            }}
          >
            {choices.map((model) => (
              <option key={model.id} value={model.id}>
                {model.name}
              </option>
            ))}
            <option value="__custom">Custom model ID…</option>
          </select>
        </label>
      </div>
      {customModel && (
        <label className="field-label">
          Custom model ID
          <input
            aria-label="Custom AI model ID"
            value={config.model}
            onChange={(e) => setConfig({ ...config, model: e.target.value })}
            spellCheck={false}
            maxLength={160}
            placeholder={
              config.provider === "openrouter"
                ? "provider/model-id"
                : "model-id"
            }
          />
        </label>
      )}
      <p>
        Choose an OpenAI preset or enter a custom model ID. Availability and
        pricing depend on your provider and account. The AI console supports
        OpenAI and OpenRouter models with tool support.
      </p>
      {config.provider === "compatible" && (
        <label className="field-label">
          API base URL
          <input
            aria-label="AI API base URL"
            placeholder="https://your-provider.example/v1"
            value={config.baseUrl}
            onChange={(e) => setConfig({ ...config, baseUrl: e.target.value })}
            spellCheck={false}
          />
        </label>
      )}
      <label className="field-label">
        API token
        <input
          type="password"
          aria-label="AI API token"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder={
            preferences?.hasToken
              ? "Saved securely · leave blank to keep"
              : "Paste your API token"
          }
          autoComplete="off"
          spellCheck={false}
          maxLength={8192}
        />
      </label>
      <div className="credential-location">
        <Shield size={15} />
        <div>
          <strong>Encrypted for your Windows account</strong>
          <code>{preferences?.storagePath || "Desktop app required"}</code>
          <span>
            The token is never returned to the UI after saving. Replace it when
            changing providers or endpoints.
          </span>
        </div>
      </div>
      {(error || preferences?.credentialError) && (
        <p className="inline-error" role="alert">
          {error || preferences?.credentialError}
        </p>
      )}
      <div className="ai-settings-actions">
        <button
          className="button primary"
          disabled={busy || !preferences?.storageAvailable}
          onClick={save}
        >
          {busy ? (
            <LoaderCircle size={14} className="spin" />
          ) : (
            <KeyRound size={14} />
          )}
          Save AI settings
        </button>
        {preferences?.hasToken && (
          <button className="button" disabled={busy} onClick={remove}>
            <Trash2 size={14} />
            Remove token
          </button>
        )}
      </div>
    </section>
  );
}
export function AIInsights({
  flows,
  title,
  preferences,
  setup,
  close,
}: {
  flows: Flow[];
  title: string;
  preferences: PreferencesStatus | null;
  setup: () => void;
  close: () => void;
}) {
  const [includeIPs, setIncludeIPs] = useState(false),
    [preview, setPreview] = useState<Preview | null>(null),
    [result, setResult] = useState<Insight | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const prepare = async () => {
    if (!window.watchmen) return;
    setError("");
    setResult(null);
    const r = await window.watchmen.previewInsights({
      flowIds: flows.slice(0, 10000).map((f) => f.id),
      includeIPs,
    });
    if (r.ok) setPreview(r.value);
    else setError(r.error);
  };
  const generate = async () => {
    if (!window.watchmen || !preview) return;
    setBusy(true);
    setError("");
    try {
      const r = await window.watchmen.runInsights(preview.id);
      if (r.ok) setResult(r.value);
      else setError(r.error);
    } catch {
      setError("AI review could not complete.");
    } finally {
      setBusy(false);
      setPreview(null);
    }
  };
  return (
    <section className="card ai-panel" aria-label="AI insights">
      <div className="card-heading">
        <div>
          <h2>
            <Sparkles size={18} />
            AI traffic analysis
          </h2>
          <p>
            {title} · {flows.length} filtered connections
          </p>
        </div>
        <button
          className="icon-button"
          aria-label="Close AI insights"
          disabled={busy}
          onClick={close}
        >
          <X size={18} />
        </button>
      </div>
      <div className="ai-panel-body">
        {!preferences?.hasToken ? (
          <div className="ai-setup">
            <p>
              Connect an AI provider in Settings to explain patterns in your
              traffic.
            </p>
            <button className="button primary" onClick={setup}>
              <KeyRound size={15} />
              Set up AI insights
            </button>
          </div>
        ) : (
          <>
            <p className="ai-disclosure">
              Share a bounded snapshot of app names, ports, protocols,
              connection states, country/network owner when available, and
              measured byte counts, and available saved application summaries
              with{" "}
              <strong>
                {preferences.ai.provider === "compatible"
                  ? preferences.ai.baseUrl
                  : preferences.ai.provider === "openai"
                    ? "OpenAI"
                    : "OpenRouter"}
              </strong>
              . Local addresses, executable paths, process IDs, and packet
              contents are excluded. Reviews are suggestions, not threat
              detection.
            </p>
            <label className="checkbox-label">
              <input
                type="checkbox"
                aria-label="Include remote IP addresses"
                checked={includeIPs}
                disabled={busy}
                onChange={(e) => {
                  setIncludeIPs(e.target.checked);
                  setPreview(null);
                }}
              />
              Include remote IP addresses (off by default)
            </label>
            <div className="ai-controls">
              <button
                className="button"
                disabled={busy || flows.length === 0}
                onClick={prepare}
              >
                Preview data to share
              </button>
              {preview && !busy && (
                <button className="button primary" onClick={generate}>
                  <Sparkles size={14} />
                  Generate insights <ArrowRight size={14} />
                </button>
              )}
              {busy && (
                <>
                  <span className="ai-loading" role="status">
                    <LoaderCircle size={15} className="spin" />
                    Reviewing snapshot…
                  </span>
                  <button
                    className="button"
                    onClick={() => window.watchmen?.cancelInsights()}
                  >
                    Cancel review
                  </button>
                </>
              )}
            </div>
            {preview && (
              <details className="ai-preview">
                <summary>
                  Review exact data · frozen at{" "}
                  {new Date(
                    String(preview.payload.capturedAt),
                  ).toLocaleTimeString()}
                </summary>
                <pre>{JSON.stringify(preview.payload, null, 2)}</pre>
              </details>
            )}
          </>
        )}
        {error && (
          <p className="inline-error" role="alert">
            {error}
          </p>
        )}
        {result && (
          <div className="ai-result">
            <div className="ai-result-meta">
              <Sparkles size={14} />
              {result.model} · {result.sampledConnections} sampled of{" "}
              {result.selectedConnections} connections · snapshot{" "}
              {new Date(result.capturedAt).toLocaleTimeString()}
            </div>
            <div>{result.text}</div>
          </div>
        )}
      </div>
    </section>
  );
}
