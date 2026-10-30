import { useState, useEffect } from "react";
import {
  Database,
  Layers,
  ArrowDownLeft,
  ArrowUpRight,
  Box,
  Globe2,
  Search,
  ChevronDown,
  ChevronRight,
  Clock,
  Info,
  RefreshCw,
  Shield,
} from "lucide-react";
import { bytes } from "./model";
import { rowAI } from "./row-overview";
export type ProfileApp = {
  id: string;
  name: string;
  path: string;
  firstSeen: number;
  lastSeen: number;
  received: number;
  sent: number;
  observations: number;
  measuredMs: number;
  observedMs: number;
  sessions: number;
  destinations: number;
};
export type ProfileDestination = {
  address: string;
  scope: string;
  country: string;
  city: string;
  org: string;
  firstSeen: number;
  lastSeen: number;
  received: number;
  sent: number;
  observations: number;
  measuredMs: number;
  applications: number;
  services: number;
};
export type ProfileSummary = {
  databasePath: string;
  schemaVersion: number;
  range: string;
  updatedAt: number;
  firstSeen: number | null;
  recording: boolean;
  eventsLost: number;
  totals: {
    applications: number;
    destinations: number;
    received: number;
    sent: number;
    observations: number;
    measuredMs: number;
    sessions: number;
  };
  applications: ProfileApp[];
  destinations: ProfileDestination[];
  daily: {
    day: string;
    received: number;
    sent: number;
    observations: number;
    measuredMs: number;
  }[];
  protocols: { protocol: string; observations: number; applications: number }[];
  countries: { country: string; destinations: number }[];
};
export type ProfileDetail = {
  application: {
    id: string;
    name: string;
    path: string;
    firstSeen: number;
    lastSeen: number;
  } | null;
  endpoints: {
    address: string;
    scope: string;
    country: string;
    org: string;
    protocol: string;
    port: number;
    localServicePort: number;
    received: number;
    sent: number;
    observations: number;
    measuredMs: number;
    firstSeen: number;
    lastSeen: number;
  }[];
};
const date = (n: number) =>
  new Date(n).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
export function TrafficProfile() {
  const [range, setRange] = useState("all"),
    [query, setQuery] = useState(""),
    [search, setSearch] = useState(""),
    [tab, setTab] = useState("applications"),
    [data, setData] = useState<ProfileSummary | null>(null),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(true),
    [selected, setSelected] = useState<string | null>(null),
    [detail, setDetail] = useState<ProfileDetail | null>(null),
    [revision, setRevision] = useState(0),
    [metric, setMetric] = useState("observations");
  useEffect(() => {
    const timer = setTimeout(() => setSearch(query), 220);
    return () => clearTimeout(timer);
  }, [query]);
  useEffect(() => {
    let active = true,
      busy = false;
    setLoading(true);
    const refresh = async () => {
      if (!window.watchmen) {
        setLoading(false);
        return;
      }
      if (busy) return;
      busy = true;
      try {
        const result = await window.watchmen.trafficProfile({ range, search });
        if (active) {
          if (result.ok) {
            setData(result.value);
            setError("");
          } else setError(result.error);
          setLoading(false);
        }
      } catch {
        if (active) {
          setError("Could not read the saved traffic profile.");
          setLoading(false);
        }
      } finally {
        busy = false;
      }
    };
    refresh();
    const timer = setInterval(refresh, 5000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [range, search, revision]);
  useEffect(() => {
    let active = true;
    setDetail(null);
    if (selected)
      window.watchmen
        ?.trafficProfileApp({ appId: selected, range })
        .then((result) => {
          if (active) {
            if (result.ok) setDetail(result.value);
            else setError(result.error);
          }
        });
    return () => {
      active = false;
    };
  }, [selected, range, data?.updatedAt]);
  const totals = data?.totals;
  const max = Math.max(
    1,
    ...(data?.daily || []).map((day) =>
      metric === "observations" ? day.observations : day.received + day.sent,
    ),
  );
  return (
    <div className="traffic-profile" aria-label="Traffic profile">
      <div className="profile-toolbar">
        <div className="profile-recording">
          <Database size={17} />
          <span>
            {data?.recording ? "Building your profile" : "Shared local profile"}
            <small>
              {data?.firstSeen
                ? `Learning since ${date(data.firstSeen)} · ${totals?.sessions} recording sessions`
                : "History begins when the collector observes your network."}
            </small>
          </span>
        </div>
        <div>
          <select
            aria-label="Profile time range"
            value={range}
            onChange={(e) => {
              setRange(e.target.value);
              setSelected(null);
            }}
          >
            <option value="all">All history</option>
            <option value="7d">Last 7 UTC days</option>
            <option value="30d">Last 30 UTC days</option>
            <option value="90d">Last 90 UTC days</option>
          </select>
          <button className="button" onClick={() => setRevision((v) => v + 1)}>
            <RefreshCw size={14} />
            Refresh profile
          </button>
        </div>
      </div>
      {error && (
        <div className="banner error" role="alert">
          <Info size={16} />
          {error}
        </div>
      )}
      {loading && !data && (
        <div className="card profile-loading">
          Loading your saved traffic profile…
        </div>
      )}
      <section className="metrics">
        <ProfileMetric
          label="Known applications"
          value={String(totals?.applications || 0)}
          sub="Stable identities across launches"
          icon={<Box size={18} />}
        />
        <ProfileMetric
          label="Known destinations"
          value={String(totals?.destinations || 0)}
          sub="Remote IPs, excluding listeners"
          icon={<Globe2 size={18} />}
        />
        <ProfileMetric
          label="Measured download"
          value={totals?.measuredMs ? bytes(totals.received) : "—"}
          sub={
            totals?.measuredMs
              ? "Saved incoming byte deltas"
              : "Detailed capture needed for bytes"
          }
          icon={<ArrowDownLeft size={18} />}
        />
        <ProfileMetric
          label="Measured upload"
          value={totals?.measuredMs ? bytes(totals.sent) : "—"}
          sub={
            totals?.measuredMs
              ? "Saved outgoing byte deltas"
              : "Connection history is still collected"
          }
          icon={<ArrowUpRight size={18} />}
        />
      </section>
      <section className="card profile-history-chart">
        <div className="card-heading">
          <div>
            <h2>
              <Layers size={16} />A pattern, over time
            </h2>
            <p>
              Recent observed days · UTC · {totals?.observations || 0} flow
              observations in this range
            </p>
          </div>
          <select
            aria-label="Profile chart metric"
            value={metric}
            onChange={(e) => setMetric(e.target.value)}
          >
            <option value="observations">Flow observations</option>
            <option value="bytes" disabled={!totals?.measuredMs}>
              Measured traffic
            </option>
          </select>
        </div>
        {data?.daily.length ? (
          <div
            className="profile-bars"
            role="img"
            aria-label="Saved daily traffic history"
          >
            {data.daily.map((day, i) => (
              <div
                className="profile-bar-cell"
                key={day.day}
                title={`${day.day} UTC · ${day.observations} flow observations · ${day.measuredMs ? bytes(day.received + day.sent) : "Bytes not measured"}`}
              >
                <div
                  className="profile-bar"
                  style={{
                    height:
                      Math.max(
                        2,
                        ((metric === "observations"
                          ? day.observations
                          : day.received + day.sent) /
                          max) *
                          120,
                      ) + "px",
                  }}
                />
                {i % Math.max(1, Math.ceil(data.daily.length / 8)) === 0 ? (
                  <small>{day.day.slice(5)}</small>
                ) : (
                  <small>&nbsp;</small>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="empty">
            <Database size={25} />
            <h3>No saved observations yet.</h3>
            <p>Keep Watchmen open to start building your profile.</p>
          </div>
        )}
        <div className="profile-tags">
          {data?.protocols.map((p) => (
            <span key={p.protocol}>
              {p.protocol}
              <b>{p.applications} apps</b>
            </span>
          ))}
          {data?.countries.map((c) => (
            <span key={c.country}>
              {c.country}
              <b>{c.destinations} IPs</b>
            </span>
          ))}
        </div>
      </section>
      <section className="card profile-list">
        <div className="card-heading">
          <div>
            <h2>Stored observations</h2>
            <p>
              App identities, recurring services, destinations, and first/last
              observations.
            </p>
          </div>
          <div className="group-switch">
            <button
              className={tab === "applications" ? "selected" : ""}
              onClick={() => {
                setTab("applications");
                setQuery("");
                setSelected(null);
              }}
            >
              Application profiles
            </button>
            <button
              className={tab === "destinations" ? "selected" : ""}
              onClick={() => {
                setTab("destinations");
                setQuery("");
                setSelected(null);
              }}
            >
              Destination profiles
            </button>
          </div>
        </div>
        <div className="profile-search search">
          <Search size={16} />
          <input
            aria-label="Search saved profiles"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={
              tab === "applications"
                ? "Search saved application names or paths…"
                : "Search saved IPs, countries, or network owners…"
            }
          />
        </div>
        <div className="profile-table-scroll">
          {tab === "applications" ? (
            <table aria-label="Saved application profiles">
              <thead>
                <tr>
                  <th>APPLICATION</th>
                  <th>DESTINATIONS</th>
                  <th>OBSERVATIONS</th>
                  <th>SESSIONS</th>
                  <th>DOWNLOAD / UPLOAD</th>
                  <th>LAST SEEN</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data?.applications.map((a) => (
                  <ProfileAppRow
                    key={a.id}
                    app={a}
                    expanded={a.id === selected}
                    detail={detail}
                    choose={() => setSelected(a.id === selected ? null : a.id)}
                  />
                ))}
              </tbody>
            </table>
          ) : (
            <table aria-label="Saved destination profiles">
              <thead>
                <tr>
                  <th>DESTINATION</th>
                  <th>APPLICATIONS</th>
                  <th>SERVICES</th>
                  <th>OBSERVATIONS</th>
                  <th>DOWNLOAD / UPLOAD</th>
                  <th>LAST SEEN</th>
                </tr>
              </thead>
              <tbody>
                {data?.destinations.map((d) => (
                  <tr
                    key={d.address}
                    {...rowAI("profile_destination", d.address, {
                      scope: d.scope,
                      country: d.country || "Unresolved",
                      networkOwner: d.org || "Unknown",
                      applications: d.applications,
                      services: d.services,
                      observations: d.observations,
                      measuredMs: d.measuredMs,
                      received: d.measuredMs ? d.received : null,
                      sent: d.measuredMs ? d.sent : null,
                    })}
                  >
                    <td>
                      <strong>{d.address}</strong>
                      <small>
                        {d.country || d.scope}
                        {d.org ? " · " + d.org : ""}
                      </small>
                    </td>
                    <td>{d.applications}</td>
                    <td>{d.services}</td>
                    <td>{d.observations}</td>
                    <td className="numeric">
                      {d.measuredMs
                        ? `${bytes(d.received)} / ${bytes(d.sent)}`
                        : "Not measured"}
                    </td>
                    <td className="profile-date">{date(d.lastSeen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
        {data &&
          (tab === "applications"
            ? data.applications.length
            : data.destinations.length) === 0 && (
            <div className="empty">
              <Search size={22} />
              <h3>No saved profiles match.</h3>
              <p>Try another search or time range.</p>
            </div>
          )}
        <div className="table-footer">
          <span>
            Up to 200 profiles · counts reflect observations, not connection
            attempts.
          </span>
          <span>
            <Clock size={12} />
            {data
              ? `Updated ${new Date(data.updatedAt).toLocaleTimeString()}`
              : "Waiting for history"}
          </span>
        </div>
      </section>
      <div className="profile-storage">
        <Shield size={15} />
        <div>
          <strong>Stored locally, across launches</strong>
          <code>{data?.databasePath || "Local desktop database"}</code>
          <p>
            Application and endpoint profiles and daily totals are retained.
            Individual connection records are retained for 30 days. Cached
            locations come from prior opt-in lookups. Overlapping windows share
            one recorder; measurement gaps are excluded.
          </p>
          {data?.eventsLost ? (
            <p className="inline-error">
              Windows reported {data.eventsLost} lost trace events in this
              range. Byte totals may be incomplete.
            </p>
          ) : null}
        </div>
      </div>
    </div>
  );
}
function ProfileMetric({
  label,
  value,
  sub,
  icon,
}: {
  label: string;
  value: string;
  sub: string;
  icon: React.ReactNode;
}) {
  return (
    <div className="card metric">
      <div className="metric-top">
        <span>{label}</span>
        <span className="metric-icon purple">{icon}</span>
      </div>
      <div className="metric-value">{value}</div>
      <div className="metric-sub">{sub}</div>
    </div>
  );
}
function ProfileAppRow({
  app: a,
  expanded,
  detail,
  choose,
}: {
  app: ProfileApp;
  expanded: boolean;
  detail: ProfileDetail | null;
  choose: () => void;
}) {
  return (
    <>
      <tr
        {...rowAI("profile_app", a.name, {
          app: a.name,
          destinations: a.destinations,
          observations: a.observations,
          sessions: a.sessions,
          measuredMs: a.measuredMs,
          received: a.measuredMs ? a.received : null,
          sent: a.measuredMs ? a.sent : null,
        })}
        className={expanded ? "selected-row" : ""}
        tabIndex={0}
        aria-label={`Saved profile ${a.name}`}
        aria-expanded={expanded}
        onClick={choose}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            choose();
          }
        }}
      >
        <td>
          <strong>{a.name}</strong>
          <small title={a.path}>
            {a.path || "Executable path unavailable · identity uses name"}
          </small>
        </td>
        <td>{a.destinations}</td>
        <td>{a.observations}</td>
        <td>{a.sessions}</td>
        <td className="numeric">
          {a.measuredMs
            ? `${bytes(a.received)} / ${bytes(a.sent)}`
            : "Not measured"}
        </td>
        <td className="profile-date">{date(a.lastSeen)}</td>
        <td>
          {expanded ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
        </td>
      </tr>
      {expanded && (
        <tr className="connection-details-row">
          <td colSpan={7}>
            <section className="profile-endpoints">
              <div className="nested-heading">
                <div>
                  <Globe2 size={16} />
                  <strong>{a.name} · learned services</strong>
                </div>
                <small>First observed {date(a.firstSeen)}</small>
              </div>
              {detail ? (
                <div className="nested-table-scroll">
                  <table aria-label="Saved application services">
                    <thead>
                      <tr>
                        <th>DESTINATION / SERVICE</th>
                        <th>PROTOCOL</th>
                        <th>OBSERVATIONS</th>
                        <th>DOWNLOAD / UPLOAD</th>
                        <th>FIRST SEEN</th>
                        <th>LAST SEEN</th>
                      </tr>
                    </thead>
                    <tbody>
                      {detail.endpoints.map((e) => (
                        <tr
                          {...rowAI(
                            "profile_service",
                            `${a.name} · ${e.address}:${e.port || e.localServicePort || ""}`,
                            {
                              app: a.name,
                              protocol: e.protocol,
                              remotePort: e.port,
                              localServicePort: e.localServicePort,
                              scope: e.scope,
                              country: e.country || "Unresolved",
                              networkOwner: e.org || "Unknown",
                              observations: e.observations,
                              measuredMs: e.measuredMs,
                              received: e.measuredMs ? e.received : null,
                              sent: e.measuredMs ? e.sent : null,
                            },
                          )}
                          key={[
                            e.address,
                            e.protocol,
                            e.port,
                            e.localServicePort,
                          ].join("|")}
                        >
                          <td>
                            <strong>
                              {e.address}
                              {e.port
                                ? `:${e.port}`
                                : e.localServicePort
                                  ? ` · local port ${e.localServicePort}`
                                  : ""}
                            </strong>
                            <small>
                              {e.country || e.scope}
                              {e.org ? " · " + e.org : ""}
                            </small>
                          </td>
                          <td>{e.protocol}</td>
                          <td>{e.observations}</td>
                          <td className="numeric">
                            {e.measuredMs
                              ? `${bytes(e.received)} / ${bytes(e.sent)}`
                              : "Not measured"}
                          </td>
                          <td className="profile-date">{date(e.firstSeen)}</td>
                          <td className="profile-date">{date(e.lastSeen)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p>Loading saved services…</p>
              )}
            </section>
          </td>
        </tr>
      )}
    </>
  );
}
