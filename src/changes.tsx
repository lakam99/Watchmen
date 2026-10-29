import { useEffect, useState } from "react";
import {
  TriangleAlert,
  Sparkles,
  Search,
  RefreshCw,
  ChevronRight,
  Check,
  X,
  Network,
  Info,
  LoaderCircle,
} from "lucide-react";
import { bytes } from "./model";
import type { PreferencesStatus, Preview, Insight } from "./ai";
export type Change = {
  id: string;
  type: string;
  app_id: string;
  app_name: string;
  address: string;
  severity: string;
  observed_at: number;
  status: string;
  evidence: {
    summary: string;
    baseline: Record<string, any>;
    observed: Record<string, any>;
    note: string;
  };
  explanation: {
    text: string;
    provider: string;
    model: string;
    generatedAt: string;
  } | null;
};
export type ChangeFeed = {
  alerts: Change[];
  counts: { total: number; open: number; spikes: number };
  learning: {
    eligibleApps: number;
    minimumObservedMs: number;
    minimumMeasuredMinutes: number;
  };
  updatedAt: number;
};
const labels: Record<string, string> = {
  new_destination: "New destination",
  new_service: "New service",
  new_country: "New country",
  traffic_spike: "Traffic spike",
};
export function Changes({
  preferences,
  setup,
  inspect,
}: {
  preferences: PreferencesStatus | null;
  setup: () => void;
  inspect: (address: string) => void;
}) {
  const [data, setData] = useState<ChangeFeed | null>(null),
    [selected, setSelected] = useState<string | null>(null),
    [status, setStatus] = useState("open"),
    [type, setType] = useState("all"),
    [search, setSearch] = useState(""),
    [revision, setRevision] = useState(0),
    [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    const refresh = async () => {
      const r = await window.watchmen?.alertsList({ status, type, search });
      if (active && r) {
        if (r.ok) {
          setData(r.value);
          setError("");
        } else setError(r.error);
      }
    };
    refresh();
    const timer = setInterval(refresh, 5000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [status, type, search, revision]);
  const chosen = data?.alerts.find((a) => a.id === selected);
  return (
    <div className="changes-view" aria-label="Connection changes">
      <div className="changes-summary">
        <div className="card">
          <TriangleAlert size={20} />
          <strong>{data?.counts.open || 0}</strong>
          <span>Open changes</span>
        </div>
        <div className="card">
          <Network size={20} />
          <strong>{data?.learning.eligibleApps || 0}</strong>
          <span>Apps with a learned baseline</span>
        </div>
        <div className="card">
          <Sparkles size={20} />
          <strong>{data?.counts.spikes || 0}</strong>
          <span>Measured traffic spikes</span>
        </div>
      </div>
      <div className="banner">
        <Info size={17} />
        <span>
          Novelty detection starts after two minutes of observed history per
          app. Spikes require five earlier measured minutes. Flags mean
          different from saved history; they do not establish malicious traffic.
        </span>
      </div>
      {error && (
        <div className="banner error" role="alert">
          {error}
        </div>
      )}
      <div className="changes-grid">
        <section className="card">
          <div className="card-heading">
            <div>
              <h2>What changed</h2>
              <p>
                Evidence is frozen before the profile learns the new
                observation.
              </p>
            </div>
            <button
              className="icon-button"
              aria-label="Refresh changes"
              onClick={() => setRevision((v) => v + 1)}
            >
              <RefreshCw size={16} />
            </button>
          </div>
          <div className="change-filters">
            <div className="search">
              <Search size={15} />
              <input
                aria-label="Search changes"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search an app or destination…"
              />
            </div>
            <select
              aria-label="Change type"
              value={type}
              onChange={(e) => setType(e.target.value)}
            >
              <option value="all">All changes</option>
              {Object.entries(labels).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
            <select
              aria-label="Change status"
              value={status}
              onChange={(e) => setStatus(e.target.value)}
            >
              <option value="open">Open</option>
              <option value="dismissed">Dismissed</option>
              <option value="all">All saved</option>
            </select>
          </div>
          <div className="change-feed">
            <table aria-label="Saved connection changes">
              <thead>
                <tr>
                  <th>CHANGE / APPLICATION</th>
                  <th>OBSERVED</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data?.alerts.map((a) => (
                  <tr
                    key={a.id}
                    tabIndex={0}
                    className={a.id === selected ? "selected-row" : ""}
                    aria-label={`Review ${labels[a.type]} for ${a.app_name}`}
                    onClick={() => setSelected(a.id)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") setSelected(a.id);
                    }}
                  >
                    <td>
                      <span className={"change-tag " + a.severity}>
                        {labels[a.type]}
                      </span>
                      <strong>{a.app_name}</strong>
                      <small>{a.address || a.evidence.summary}</small>
                    </td>
                    <td className="profile-date">
                      {new Date(a.observed_at).toLocaleString(undefined, {
                        month: "short",
                        day: "numeric",
                        hour: "numeric",
                        minute: "2-digit",
                      })}
                      <small>{a.status}</small>
                    </td>
                    <td>
                      <ChevronRight size={15} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!data?.alerts.length && (
              <div className="empty">
                <Check size={25} />
                <h3>No matching changes.</h3>
                <p>
                  The saved baseline will build as you monitor. Unmeasured
                  traffic never produces byte-spike alerts.
                </p>
              </div>
            )}
          </div>
          <div className="table-footer">
            <span>Up to 200 saved changes · dismissing is reversible.</span>
          </div>
        </section>
        {chosen ? (
          <ChangeDetail
            key={chosen.id}
            change={chosen}
            preferences={preferences}
            setup={setup}
            inspect={inspect}
            refresh={() => setRevision((v) => v + 1)}
          />
        ) : (
          <section className="card change-placeholder">
            <TriangleAlert size={28} />
            <h2>Select a change</h2>
            <p>
              Compare before and after, inspect packets, or ask OpenRouter to
              explain the recorded evidence.
            </p>
          </section>
        )}
      </div>
    </div>
  );
}
function ChangeDetail({
  change: a,
  preferences,
  setup,
  inspect,
  refresh,
}: {
  change: Change;
  preferences: PreferencesStatus | null;
  setup: () => void;
  inspect: (address: string) => void;
  refresh: () => void;
}) {
  const [includeIPs, setIncludeIPs] = useState(false),
    [preview, setPreview] = useState<Preview | null>(null),
    [busy, setBusy] = useState(false),
    [reply, setReply] = useState<Change["explanation"]>(a.explanation),
    [error, setError] = useState("");
  const b = a.evidence.baseline,
    o = a.evidence.observed;
  const explain = async () => {
    if (!preferences?.hasToken) {
      setup();
      return;
    }
    setError("");
    const r = await window.watchmen?.previewAlert(a.id, includeIPs);
    if (r) {
      if (r.ok) setPreview(r.value);
      else setError(r.error);
    }
  };
  const generate = async () => {
    if (!preview) return;
    setBusy(true);
    setError("");
    try {
      const r = await window.watchmen?.runInsights(preview.id);
      if (r) {
        if (r.ok) {
          setReply(r.value);
          refresh();
        } else setError(r.error);
      }
    } finally {
      setBusy(false);
      setPreview(null);
    }
  };
  return (
    <section className="card change-detail">
      <div className="card-heading">
        <div>
          <h2>{labels[a.type]}</h2>
          <p>
            {a.app_name} · {new Date(a.observed_at).toLocaleTimeString()}
          </p>
        </div>
        <span className={"change-tag " + a.severity}>
          {a.severity === "review" ? "Review" : "Notice"}
        </span>
      </div>
      <div className="change-detail-body">
        <h3>Why it was flagged</h3>
        <p>{a.evidence.summary}</p>
        <div className="before-after">
          <div>
            <small>SAVED BASELINE</small>
            {a.type === "new_destination" ? (
              <strong>{b.knownDestinations} known destination IPs</strong>
            ) : a.type === "new_service" ? (
              <strong>
                {b.usualServices
                  ?.map((p: any) => `${p.protocol}/${p.port}`)
                  .join(", ") || "No remote services recorded"}
              </strong>
            ) : a.type === "new_country" ? (
              <strong>{b.knownCountries?.join(", ")}</strong>
            ) : (
              <strong>
                {bytes(b.medianBytesPerSecond, true)} median{" "}
                {b.direction === "sent" ? "upload" : "download"}
                <span>
                  {b.windows} measured minutes · threshold{" "}
                  {bytes(b.thresholdBytesPerSecond, true)}
                </span>
              </strong>
            )}
          </div>
          <div>
            <small>NEW OBSERVATION</small>
            {a.type === "traffic_spike" ? (
              <strong>
                {bytes(o.bytesPerSecond, true)}
                <span>
                  {bytes(o.bytes)} in {(o.measuredMs / 1000).toFixed(0)}{" "}
                  measured seconds ·{" "}
                  {o.ratio
                    ? o.ratio.toFixed(1) + "× baseline"
                    : "baseline near zero"}
                </span>
              </strong>
            ) : (
              <strong>
                {o.country || o.address}
                <span>
                  {o.protocol
                    ? `${o.protocol} · port ${o.port}`
                    : "Approximate IP location"}
                </span>
              </strong>
            )}
          </div>
        </div>
        <p className="change-note">{a.evidence.note}</p>
        <div className="ai-controls">
          {a.address && (
            <button className="button" onClick={() => inspect(a.address)}>
              <Network size={14} />
              Inspect packets
            </button>
          )}
          <button
            className="button"
            onClick={async () => {
              const r = await window.watchmen?.alertStatus(
                a.id,
                a.status === "open" ? "dismissed" : "open",
              );
              if (r && !r.ok) setError(r.error);
              else refresh();
            }}
          >
            {a.status === "open" ? <X size={14} /> : <Check size={14} />}{" "}
            {a.status === "open" ? "Dismiss" : "Reopen"}
          </button>
        </div>
        <div className="change-ai">
          <h3>
            <Sparkles size={16} />
            Explain what changed
          </h3>
          <p>
            Uses the frozen metadata below and your configured AI provider.
            Packet payloads, local addresses, paths, and process IDs are
            excluded.
          </p>
          <label className="checkbox-label">
            <input
              type="checkbox"
              aria-label="Include change destination IP"
              checked={includeIPs}
              disabled={busy}
              onChange={(e) => {
                setIncludeIPs(e.target.checked);
                setPreview(null);
              }}
            />
            Include the destination IP (off by default)
          </label>
          <button className="button primary" disabled={busy} onClick={explain}>
            <Sparkles size={14} />
            {reply ? "Review another explanation" : "Explain this change"}
          </button>
          {preview && (
            <>
              <details className="ai-preview">
                <summary>Review exact metadata to share</summary>
                <pre>{JSON.stringify(preview.payload, null, 2)}</pre>
              </details>
              <button className="button primary full" onClick={generate}>
                Generate explanation
              </button>
            </>
          )}
          {busy && (
            <div className="ai-controls">
              <span className="ai-loading" role="status">
                <LoaderCircle className="spin" size={15} />
                Explaining the change…
              </span>
              <button
                className="button"
                onClick={() => window.watchmen?.cancelInsights()}
              >
                Cancel explanation
              </button>
            </div>
          )}
          {reply && (
            <div className="ai-result">
              <div className="ai-result-meta">
                {reply.provider} · {reply.model} · saved{" "}
                {new Date(reply.generatedAt).toLocaleTimeString()}
              </div>
              <div>{reply.text}</div>
            </div>
          )}
          {error && (
            <p className="inline-error" role="alert">
              {error}
            </p>
          )}
        </div>
      </div>
    </section>
  );
}
