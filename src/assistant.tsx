import { useEffect, useRef, useState } from "react";
import {
  Bot,
  Send,
  Square,
  ShieldCheck,
  Globe2,
  Radio,
  Terminal,
  Trash2,
  ExternalLink,
  Check,
  X,
  LoaderCircle,
  Settings2,
  ChevronRight,
} from "lucide-react";
import type { PreferencesStatus, Result } from "./ai";
export type AssistantOptions = {
  shareIPs: boolean;
  ipLookups: boolean;
  webSearch: boolean;
};
type Source = { url: string; title: string };
type Message = {
  id: string;
  role: "user" | "assistant" | "event";
  text: string;
  at: number;
  sources?: Source[];
  summarySource?: "model" | "local";
};
type Trace = {
  id: string;
  tool: string;
  status: string;
  at: number;
  arguments: Record<string, unknown> | null;
  result: Record<string, unknown> | null;
};
type Proposal = {
  id: string;
  operation: "block" | "unblock";
  status: string;
  expires: number;
  requiresAcknowledgement: boolean;
  result?: string;
  target: {
    kind: string;
    label: string;
    appPath: string;
    address: string;
    port: number;
    protocol: string;
    countries?: string[];
  };
};
export type AssistantState = {
  revision: number;
  busy: boolean;
  actionBusy: boolean;
  phase: string;
  error: string | null;
  options: AssistantOptions;
  messages: Message[];
  trace: Trace[];
  proposals: Proposal[];
  sessionOnly: true;
};
const toolNames: Record<string, string> = {
  network_status: "Read live telemetry",
  list_applications: "List current applications",
  inspect_connections: "Inspect connections",
  traffic_profile: "Read saved profiles",
  connection_changes: "Read connection changes",
  network_rules: "Refresh network rules",
  lookup_destination: "Public IP lookup",
  search_web: "Web research",
  propose_block: "Prepare block review",
  propose_unblock: "Prepare unblock review",
};
const reviewText = (value: string) =>
  value.replace(
    /[\u200e\u200f\u202a-\u202e\u2066-\u2069]/g,
    (char) => "\\u" + char.charCodeAt(0).toString(16).padStart(4, "0"),
  );
export function AIConsole({
  preferences,
  admin,
  setup,
  elevate,
  navigate,
}: {
  preferences: PreferencesStatus | null;
  admin: boolean;
  setup: () => void;
  elevate: () => void;
  navigate: (page: string) => void;
}) {
  const [state, setState] = useState<AssistantState | null>(null),
    [draft, setDraft] = useState(""),
    [error, setError] = useState(""),
    [localBusy, setLocalBusy] = useState(false),
    [ack, setAck] = useState<Record<string, boolean>>({});
  const transcript = useRef<HTMLDivElement>(null),
    input = useRef<HTMLTextAreaElement>(null);
  const accept = (next: AssistantState) =>
    setState((old) => (old && old.revision > next.revision ? old : next));
  useEffect(() => {
    const bridge = window.watchmen;
    if (!bridge) return;
    let active = true;
    const update = (next: AssistantState) => {
      if (active) accept(next);
    };
    const off = bridge.onAssistant(update);
    const poll = () =>
      bridge.assistantStatus().then((r) => {
        if (active) {
          if (r.ok) update(r.value);
          else setError(r.error);
        }
      });
    poll();
    const timer = setInterval(poll, 5000);
    return () => {
      active = false;
      off();
      clearInterval(timer);
    };
  }, []);
  useEffect(() => {
    if (transcript.current)
      transcript.current.scrollTop = transcript.current.scrollHeight;
  }, [state?.messages.length, state?.phase]);
  const ready =
    preferences?.hasToken &&
    ["openai", "openrouter"].includes(preferences.ai.provider);
  const providerName =
    preferences?.ai.provider === "openai" ? "OpenAI" : "OpenRouter";
  const busy = !!state?.busy || !!state?.actionBusy || localBusy;
  async function run(request: () => Promise<Result<AssistantState>>) {
    setError("");
    setLocalBusy(true);
    try {
      const r = await request();
      if (r.ok) accept(r.value);
      else setError(r.error);
    } catch {
      setError("The AI console could not complete this operation.");
    } finally {
      setLocalBusy(false);
    }
  }
  async function send() {
    if (!draft.trim() || !window.watchmen || busy) return;
    const text = draft;
    setDraft("");
    await run(() => window.watchmen!.assistantSend(text));
  }
  const options = state?.options || {
    shareIPs: false,
    ipLookups: false,
    webSearch: false,
  };
  const configure = async (key: keyof AssistantOptions, value: boolean) => {
    if (!state || !window.watchmen) return;
    const before = state;
    const next = { ...options, [key]: value };
    setState({ ...state, options: next });
    await run(async () => {
      try {
        const result = await window.watchmen!.assistantConfigure({
          [key]: value,
        });
        if (!result.ok) setState(before);
        return result;
      } catch (error) {
        setState(before);
        throw error;
      }
    });
  };
  const openSource = async (url: string) => {
    const r = await window.watchmen?.assistantSource(url);
    if (r && !r.ok) setError(r.error);
  };
  return (
    <section className="ai-console" aria-label="AI command console">
      <div className="console-grid">
        <div className="card console-chat">
          <div className="console-panel-heading">
            <div>
              <Bot size={17} />
              <h2>COMMS / AI ASSISTANT</h2>
            </div>
            <span className="console-link-state">
              {ready
                ? `${providerName} / ${preferences?.ai.model}`
                : "NOT CONFIGURED"}
            </span>
          </div>
          <div className="console-session-note">
            <ShieldCheck size={14} />
            <span>
              Session only. Messages go to {providerName} as written. Tool
              output excludes executable paths, private IPs and packet content.
              Public destination IPs are optional.
            </span>
          </div>
          <div
            className="console-transcript"
            ref={transcript}
            role="log"
            aria-label="AI conversation"
            aria-live="polite"
            aria-relevant="additions"
          >
            {!state?.messages.length && (
              <div className="console-welcome">
                <Terminal size={30} />
                <div className="eyebrow">COMMAND INTERFACE READY</div>
                <h3>Investigate. Review. Act.</h3>
                <p>
                  Ask about current traffic, compare saved profiles, research
                  public destinations, or prepare a scoped block. Watchmen
                  requires your approval before changing a network rule.
                </p>
                <div className="console-prompts">
                  {[
                    "Show the top applications and inspect their connections.",
                    "What changed compared with my saved traffic profiles?",
                    "List the active Watchmen network rules.",
                  ].map((text) => (
                    <button
                      className="button"
                      key={text}
                      onClick={() => {
                        setDraft(text);
                        input.current?.focus();
                      }}
                    >
                      {text}
                      <ChevronRight size={13} />
                    </button>
                  ))}
                </div>
              </div>
            )}
            {state?.messages.map((m) => (
              <article className={"console-message " + m.role} key={m.id}>
                <header>
                  <span>
                    {m.role === "user"
                      ? "OPERATOR"
                      : m.role === "assistant"
                        ? m.summarySource === "local"
                          ? "COLLECTED RESULTS"
                          : "AI ASSISTANT"
                        : "HOST EVENT"}
                  </span>
                  <time>
                    {new Date(m.at).toLocaleTimeString([], { hour12: false })}
                  </time>
                </header>
                <p>{m.text}</p>
                {!!m.sources?.length && (
                  <div className="console-sources">
                    {m.sources.map((s) => (
                      <button key={s.url} onClick={() => openSource(s.url)}>
                        <ExternalLink size={12} />
                        {s.title}
                      </button>
                    ))}
                  </div>
                )}
              </article>
            ))}
            {state?.busy && (
              <div className="console-thinking" role="status">
                <LoaderCircle className="spin" size={14} />
                {state.phase}
              </div>
            )}
          </div>
          <div className="console-composer">
            {!ready && (
              <div className="console-setup">
                <span>
                  Configure an OpenAI or OpenRouter token and a model with tool
                  support.
                </span>
                <button className="button" onClick={setup}>
                  <Settings2 size={14} />
                  AI settings
                </button>
              </div>
            )}
            <label className="console-input-label" htmlFor="console-input">
              OPERATOR INPUT{" "}
              <span>Enter to send / Shift+Enter for newline</span>
            </label>
            <textarea
              id="console-input"
              ref={input}
              aria-label="Message AI assistant"
              value={draft}
              maxLength={4000}
              disabled={!ready || busy}
              placeholder="Ask about traffic, research a destination, or request an app task…"
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (
                  e.key === "Enter" &&
                  !e.shiftKey &&
                  !e.nativeEvent.isComposing
                ) {
                  e.preventDefault();
                  send();
                }
              }}
            />
            <div className="console-composer-actions">
              <span>
                {draft.length.toLocaleString()} / 4,000 · up to 6 tool rounds +
                final summary
              </span>
              <button
                className="button"
                disabled={busy || !state?.messages.length}
                onClick={() => run(() => window.watchmen!.assistantReset())}
              >
                <Trash2 size={13} />
                Clear session
              </button>
              {state?.busy ? (
                <button
                  className="button"
                  onClick={() =>
                    window.watchmen?.assistantCancel().then((r) => {
                      if (r.ok) accept(r.value);
                      else setError(r.error);
                    })
                  }
                >
                  <Square size={13} />
                  Stop response
                </button>
              ) : (
                <button
                  className="button primary"
                  disabled={!ready || busy || !draft.trim()}
                  onClick={send}
                >
                  <Send size={14} />
                  Send
                </button>
              )}
            </div>
          </div>
        </div>
        <aside
          className="console-tools"
          aria-label="AI tools and action reviews"
        >
          <section className="card console-capabilities">
            <div className="console-panel-heading">
              <h2>
                <ShieldCheck size={15} />
                TOOL PERMISSIONS
              </h2>
            </div>
            <div className="console-capabilities-body">
              <div className="console-capability">
                <Radio size={14} />
                <span>Local traffic & history</span>
                <b>READ ONLY</b>
              </div>
              <div className="console-capability">
                <ShieldCheck size={14} />
                <span>Network actions</span>
                <b>REVIEW</b>
              </div>
              {(
                [
                  ["shareIPs", "Share public destination IPs"],
                  ["ipLookups", "Allow public IP lookups"],
                  ["webSearch", "Allow web research"],
                ] as const
              ).map(([key, label]) => (
                <label className="console-permission" key={key}>
                  <input
                    type="checkbox"
                    checked={options[key]}
                    disabled={busy}
                    onChange={(e) => configure(key, e.target.checked)}
                  />
                  {label}
                </label>
              ))}
              <p>
                Changing permissions clears this session. IP lookups send a
                public IP to ipwho.is. Web research sends a public query through{" "}
                {providerName} and may add search charges. Enabling a permission
                alone does not make a lookup.
              </p>
              <p>
                Chat and tool results are held in memory. These permission
                choices are saved locally.
              </p>
            </div>
          </section>
          {state?.proposals.map((p) => (
            <section
              className="card console-review"
              key={p.id}
              aria-label="AI action review"
            >
              <div className="console-panel-heading">
                <h2>
                  {p.operation === "block" ? "BLOCK REVIEW" : "UNBLOCK REVIEW"}
                </h2>
                <span className={"console-action-status " + p.status}>
                  {p.status.replaceAll("_", " ")}
                </span>
              </div>
              <div className="console-review-body">
                <h3>{reviewText(p.target.label || p.target.kind)}</h3>
                <dl>
                  <dt>Scope</dt>
                  <dd>
                    {p.operation === "unblock"
                      ? "Disable one saved " + p.target.kind + " rule"
                      : p.target.kind === "app"
                        ? "Entire application / all destinations"
                        : p.target.kind === "destination"
                          ? "Destination IP / all applications"
                          : "One app / IP / protocol / port"}
                  </dd>
                  {p.target.appPath && (
                    <>
                      <dt>Executable · local review only</dt>
                      <dd>
                        <code>{reviewText(p.target.appPath)}</code>
                      </dd>
                    </>
                  )}
                  {p.target.address && (
                    <>
                      <dt>Remote target · local review only</dt>
                      <dd>
                        <code>
                          {p.target.address}
                          {p.target.port ? ":" + p.target.port : ""}{" "}
                          {p.target.protocol}
                        </code>
                      </dd>
                    </>
                  )}
                  {!!p.target.countries?.length && (
                    <>
                      <dt>Countries</dt>
                      <dd>{p.target.countries.join(", ")}</dd>
                    </>
                  )}
                </dl>
                {p.status === "pending" && (
                  <>
                    <p>
                      No change has been made. This review expires at{" "}
                      {new Date(p.expires).toLocaleTimeString()}. Other saved
                      rules can overlap.
                    </p>
                    {p.requiresAcknowledgement && (
                      <label className="console-permission">
                        <input
                          type="checkbox"
                          checked={!!ack[p.id]}
                          onChange={(e) =>
                            setAck((v) => ({ ...v, [p.id]: e.target.checked }))
                          }
                        />
                        I understand this disables a broad isolation or regional
                        policy.
                      </label>
                    )}
                    {!admin && (
                      <p className="console-admin-note">
                        Administrator access is required. After restarting, ask
                        for a fresh review; chat sessions do not survive
                        restart.
                      </p>
                    )}
                    <div className="console-review-actions">
                      <button
                        className="button"
                        disabled={busy}
                        onClick={() =>
                          run(() => window.watchmen!.assistantReject(p.id))
                        }
                      >
                        <X size={13} />
                        Reject
                      </button>
                      {admin ? (
                        <button
                          className="button"
                          disabled={
                            busy || (p.requiresAcknowledgement && !ack[p.id])
                          }
                          onClick={() =>
                            run(() =>
                              window.watchmen!.assistantApprove(
                                p.id,
                                !!ack[p.id],
                              ),
                            )
                          }
                        >
                          <Check size={13} />
                          Approve {p.operation}
                        </button>
                      ) : (
                        <button
                          className="button"
                          disabled={busy}
                          onClick={elevate}
                        >
                          Restart as administrator
                        </button>
                      )}
                    </div>
                  </>
                )}
                {p.result && (
                  <p className="console-action-result" role="status">
                    {p.result}
                  </p>
                )}
                {p.status !== "pending" && (
                  <button
                    className="text-button"
                    onClick={() => navigate("Network rules")}
                  >
                    Inspect network rules <ChevronRight size={13} />
                  </button>
                )}
              </div>
            </section>
          ))}
          <section className="card console-tool-log">
            <div className="console-panel-heading">
              <h2>
                <Terminal size={15} />
                TOOL ACTIVITY
              </h2>
              <span>{state?.trace.length || 0}</span>
            </div>
            <div className="console-traces">
              {!state?.trace.length && (
                <p className="console-tool-empty">
                  Tool calls appear here as the assistant works. No shell,
                  arbitrary URLs, file access or bulk network actions are
                  exposed.
                </p>
              )}
              {state?.trace
                .slice()
                .reverse()
                .map((t) => (
                  <details key={t.id} className="console-trace">
                    <summary>
                      <span className={"tool-indicator " + t.status} />
                      <span>{toolNames[t.tool] || t.tool}</span>
                      <small>{t.status}</small>
                    </summary>
                    <pre>
                      {JSON.stringify(
                        { arguments: t.arguments, result: t.result },
                        null,
                        2,
                      )}
                    </pre>
                  </details>
                ))}
            </div>
          </section>
        </aside>
      </div>
      {(error || state?.error) && (
        <div className="banner error" role="alert">
          {error || state?.error}
        </div>
      )}
      <footer className="console-footer">
        <Globe2 size={13} />
        External findings are untrusted evidence. Model statements do not
        authorize actions; local review cards do.
      </footer>
    </section>
  );
}
