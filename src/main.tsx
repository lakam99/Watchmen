import { version as appVersion } from "../package.json";
import React, { useState, useEffect, useMemo } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  ArrowDownLeft,
  ArrowUpRight,
  ArrowDown,
  ArrowUp,
  Box,
  Globe2,
  Network,
  Settings2,
  Search,
  Download,
  Pause,
  Play,
  Shield,
  ChevronRight,
  ChevronDown,
  X,
  ExternalLink,
  Radio,
  Layers,
  Clock,
  Info,
  LocateFixed,
  SlidersHorizontal,
  Check,
  Monitor,
  ArrowRight,
  FolderOpen,
  Moon,
  Sun,
  Sparkles,
  Database,
  TriangleAlert,
  Bot,
} from "lucide-react";
import {
  bytes,
  groupFlows,
  scope,
  type Snapshot,
  type GroupBy,
  type Group,
  type Flow,
} from "./model";
import "./style.css";
import "./additions.css";
import "./profile.css";
import "./inspection.css";
import "./rules.css";
import "./terminal.css";
import "./assistant.css";
import {
  AIConsole,
  type AssistantState,
  type AssistantOptions,
} from "./assistant";
import {
  RuleProvider,
  RuleStatusBanner,
  NetworkRules,
  RuleActions,
  type RuleState,
  type RuleCatalog,
  type RulePreview,
  type RuleInput,
} from "./rules";
import { Changes, type ChangeFeed } from "./changes";
import { PacketInspector, type PacketState, type Packet } from "./packets";
import {
  TrafficProfile,
  type ProfileSummary,
  type ProfileDetail,
} from "./profile";
import {
  AISettings,
  AIInsights,
  type PreferencesStatus,
  type Result,
  type Preview,
  type Insight,
  type AIConfig,
} from "./ai";
import { UpdateBanner, UpdateSettings, type UpdateState } from "./updates";
import { RowOverviewUI, rowAI, type RowInfo } from "./row-overview";
declare global {
  interface Window {
    watchmen?: {
      assistantStatus: () => Promise<Result<AssistantState>>;
      assistantSend: (text: string) => Promise<Result<AssistantState>>;
      assistantRaiseLimit: (id?: string) => Promise<Result<AssistantState>>;
      assistantCheckpoint: (id?: string) => Promise<Result<AssistantState>>;
      assistantCancel: () => Promise<Result<AssistantState>>;
      assistantReset: () => Promise<Result<AssistantState>>;
      assistantConfigure: (
        options: Partial<AssistantOptions>,
      ) => Promise<Result<AssistantState>>;
      assistantApprove: (
        id: string,
        acknowledged: boolean,
      ) => Promise<Result<AssistantState>>;
      assistantReject: (id: string) => Promise<Result<AssistantState>>;
      assistantSource: (url: string) => Promise<Result<void>>;
      onAssistant: (fn: (state: AssistantState) => void) => () => void;
      onSnapshot: (fn: (s: Snapshot) => void) => () => void;
      updatesStatus: () => Promise<Result<UpdateState>>;
      updatesCheck: () => Promise<Result<UpdateState>>;
      updatesDownload: () => Promise<Result<UpdateState>>;
      updatesConfigure: (input: {
        autoCheck: boolean;
        autoDownload: boolean;
      }) => Promise<Result<UpdateState>>;
      updatesInstall: () => Promise<Result<UpdateState>>;
      updatesRelease: () => Promise<Result<void>>;
      getStatus: () => Promise<Snapshot>;
      firewallStatus: (refresh?: boolean) => Promise<Result<RuleState>>;
      firewallCatalog: () => Promise<Result<RuleCatalog>>;
      openRuleDataSource: () => Promise<Result<boolean>>;
      firewallPreview: (input: RuleInput) => Promise<Result<RulePreview>>;
      firewallApply: (id: string) => Promise<Result<RuleState>>;
      firewallToggle: (
        id: string,
        enabled: boolean,
      ) => Promise<Result<RuleState>>;
      firewallForget: (id: string) => Promise<Result<RuleState>>;
      firewallCancel: () => Promise<Result<RuleState>>;
      firewallUnblockAll: () => Promise<Result<RuleState>>;
      firewallPickApp: (only?: boolean) => Promise<Result<RulePreview | null>>;
      setLocations: (enabled: boolean) => Promise<boolean>;
      exportSession: () => Promise<{
        ok?: boolean;
        canceled?: boolean;
        error?: string;
      }>;
      openPath: (pid: number) => Promise<boolean>;
      relaunchElevated: () => Promise<boolean>;
      viewSettings: () => Promise<
        Result<{
          page: string;
          group: GroupBy;
          filter: string;
          lifecycle: string;
          direction: string;
          sort: string;
          adapter: string;
          windowSize: number;
          search: string;
        }>
      >;
      saveViewSettings: (
        input: Record<string, unknown>,
      ) => Promise<Result<unknown>>;
      dismissAllChanges: () => Promise<Result<number>>;
      preferences: () => Promise<Result<PreferencesStatus>>;
      rowOverview: (
        input: RowInfo & { id: string },
      ) => Promise<Result<Insight>>;
      rowOverviewCancel: (id: string) => Promise<Result<boolean>>;
      setTheme: (
        theme: "system" | "light" | "dark",
      ) => Promise<Result<PreferencesStatus>>;
      saveAI: (
        config: AIConfig & { token: string },
      ) => Promise<Result<PreferencesStatus>>;
      removeAIToken: () => Promise<Result<PreferencesStatus>>;
      previewInsights: (request: {
        flowIds: string[];
        includeIPs: boolean;
      }) => Promise<Result<Preview>>;
      runInsights: (id: string) => Promise<Result<Insight>>;
      cancelInsights: () => Promise<Result<boolean>>;
      alertsList: (options: {
        status: string;
        type: string;
        search: string;
      }) => Promise<Result<ChangeFeed>>;
      alertStatus: (id: string, status: string) => Promise<Result<boolean>>;
      previewAlert: (
        id: string,
        includeIPs: boolean,
      ) => Promise<Result<Preview>>;
      packetsStatus: () => Promise<Result<PacketState>>;
      packetsStart: (seconds: number) => Promise<Result<PacketState>>;
      packetsStop: () => Promise<Result<PacketState>>;
      packetsImport: () => Promise<Result<PacketState | null>>;
      packetDetail: (id: string) => Promise<Result<Packet>>;
      trafficProfile: (options: {
        range: string;
        search?: string;
      }) => Promise<Result<ProfileSummary>>;
      trafficProfileApp: (options: {
        appId: string;
        range: string;
      }) => Promise<Result<ProfileDetail>>;
    };
  }
}
type Sample = { time: string; rx: number; tx: number };
const empty: Snapshot = {
  timestamp: "",
  startedAt: "",
  admin: false,
  tracing: false,
  traceError: null,
  errors: [],
  eventsLost: 0,
  evictedFlows: 0,
  rxRate: 0,
  txRate: 0,
  adapters: [],
  flows: [],
  locationsEnabled: false,
  locationStatus: "Off",
  locations: {},
  agentError: null,
};
function App() {
  const [data, setData] = useState<Snapshot>(empty),
    [history, setHistory] = useState<Sample[]>([]),
    [paused, setPaused] = useState(false),
    [page, setPage] = useState("Overview"),
    [group, setGroup] = useState<GroupBy>("app"),
    [search, setSearch] = useState(""),
    [filter, setFilter] = useState("all"),
    [lifecycle, setLifecycle] = useState("active"),
    [direction, setDirection] = useState("both"),
    [sort, setSort] = useState("connections"),
    [selected, setSelected] = useState<string | null>(null),
    [settings, setSettings] = useState(false),
    [notice, setNotice] = useState(""),
    [adapter, setAdapter] = useState("all"),
    [windowSize, setWindowSize] = useState(60),
    [preferences, setPreferences] = useState<PreferencesStatus | null>(null),
    [viewLoaded, setViewLoaded] = useState(false),
    [assistantActivity, setAssistantActivity] = useState({
      busy: false,
      pending: 0,
    }),
    [theme, setTheme] = useState<"system" | "light" | "dark">("system"),
    [showAI, setShowAI] = useState(false),
    [connection, setConnection] = useState<string | null>(null),
    [packetSearch, setPacketSearch] = useState("");
  useEffect(() => {
    const setup = () => setSettings(true);
    window.addEventListener("watchmen-ai-settings", setup);
    return () => window.removeEventListener("watchmen-ai-settings", setup);
  }, []);
  useEffect(() => {
    const bridge = window.watchmen;
    if (!bridge) return;
    let active = true;
    const update = (s: AssistantState) => {
      if (active)
        setAssistantActivity({
          busy: s.busy || s.actionBusy,
          pending: s.proposals.filter((p) => p.status === "pending").length,
        });
    };
    const off = bridge.onAssistant(update);
    bridge.assistantStatus().then((r) => {
      if (r.ok) update(r.value);
    });
    return () => {
      active = false;
      off();
    };
  }, []);
  useEffect(() => {
    window.watchmen?.preferences().then((r) => {
      if (r.ok) {
        setPreferences(r.value);
        setTheme(r.value.theme);
        if (r.value.error) setNotice(r.value.error);
      }
    });
  }, []);
  useEffect(() => {
    let active = true;
    window.watchmen?.viewSettings().then((r) => {
      if (active && r.ok) {
        const v = r.value;
        setPage(v.page);
        setGroup(v.group);
        setFilter(v.filter);
        setLifecycle(v.lifecycle);
        setDirection(v.direction);
        setSort(v.sort);
        setAdapter(v.adapter);
        setWindowSize(v.windowSize);
        setSearch(v.search);
      }
      if (active) setViewLoaded(true);
    });
    return () => {
      active = false;
    };
  }, []);
  useEffect(() => {
    if (!viewLoaded) return;
    const timer = setTimeout(() => {
      window.watchmen
        ?.saveViewSettings({
          page,
          group,
          filter,
          lifecycle,
          direction,
          sort,
          adapter,
          windowSize,
          search: search.slice(0, 200),
        })
        .then((r) => {
          if (r && !r.ok) setNotice(r.error);
        });
    }, 250);
    return () => clearTimeout(timer);
  }, [
    viewLoaded,
    page,
    group,
    filter,
    lifecycle,
    direction,
    sort,
    adapter,
    windowSize,
    search,
  ]);
  useEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const apply = () => {
      document.documentElement.dataset.theme =
        theme === "system" ? (mq.matches ? "dark" : "light") : theme;
    };
    apply();
    mq.addEventListener("change", apply);
    return () => mq.removeEventListener("change", apply);
  }, [theme]);
  const changeTheme = async (value: "system" | "light" | "dark") => {
    if (window.watchmen) {
      const r = await window.watchmen.setTheme(value);
      if (!r.ok) {
        setNotice(r.error);
        return;
      }
      setPreferences(r.value);
    }
    setTheme(value);
  };
  useEffect(() => {
    if (!window.watchmen) return;
    let alive = true;
    const apply = (s: Snapshot) => {
      if (!alive) return;
      if (paused) {
        setData((current) => ({
          ...current,
          alertCount: s.alertCount,
          locationsEnabled: s.locationsEnabled,
          locationStatus: s.locationStatus,
          locations: s.locations,
          profileStatus: s.profileStatus,
          agentError: s.agentError,
        }));
        return;
      }
      setData({ ...empty, ...s });
      if (s.timestamp)
        setHistory((h) =>
          h.at(-1)?.time === s.timestamp
            ? h
            : [
                ...h,
                {
                  time: s.timestamp,
                  rx:
                    adapter === "all"
                      ? s.rxRate
                      : s.adapters.find((a) => a.id === adapter)?.rxRate || 0,
                  tx:
                    adapter === "all"
                      ? s.txRate
                      : s.adapters.find((a) => a.id === adapter)?.txRate || 0,
                },
              ].slice(-300),
        );
    };
    window.watchmen.getStatus().then(apply);
    const off = window.watchmen.onSnapshot(apply);
    return () => {
      alive = false;
      off();
    };
  }, [paused, adapter]);
  useEffect(() => {
    if (notice) {
      const timer = setTimeout(() => setNotice(""), 5500);
      return () => clearTimeout(timer);
    }
  }, [notice]);
  const flows = useMemo(
    () =>
      data.flows.filter((f) => {
        if (lifecycle === "active" && !f.active) return false;
        if (lifecycle === "connected" && scope(f.remoteAddress) === "listener")
          return false;
        if (filter !== "all" && scope(f.remoteAddress) !== filter) return false;
        if (
          (direction === "in" && f.received === 0) ||
          (direction === "out" && f.sent === 0)
        )
          return false;
        const loc = data.locations[f.remoteAddress];
        return [
          f.app,
          f.pid,
          f.remoteAddress,
          f.remotePort,
          f.localAddress,
          f.protocol,
          f.state,
          loc?.country,
          loc?.org,
          loc?.city,
        ]
          .join(" ")
          .toLowerCase()
          .includes(search.toLowerCase());
      }),
    [data, search, filter, lifecycle, direction],
  );
  const groups = useMemo(
    () =>
      groupFlows(flows, group, data.locations).sort((a, b) =>
        sort === "name"
          ? a.name.localeCompare(b.name)
          : sort === "download"
            ? b.rxRate - a.rxRate
            : sort === "upload"
              ? b.txRate - a.txRate
              : sort === "total"
                ? b.received + b.sent - a.received - a.sent
                : b.flows.length - a.flows.length,
      ),
    [flows, group, data.locations, sort],
  );
  const chosen = groups.find((g) => g.id === selected);
  const inspected = chosen?.flows.find((f) => f.id === connection);
  const active = data.flows.filter(
    (f) => f.active && scope(f.remoteAddress) !== "listener",
  );
  const publicIPs = new Set(
    active
      .filter((f) => scope(f.remoteAddress) === "internet")
      .map((f) => f.remoteAddress),
  );
  const appCount = new Set(active.map((f) => f.app + "|" + f.processPath)).size;
  const currentAdapter = data.adapters.find((a) => a.id === adapter);
  const rx = adapter === "all" ? data.rxRate : currentAdapter?.rxRate || 0,
    tx = adapter === "all" ? data.txRate : currentAdapter?.txRate || 0;
  const latest = data.timestamp ? new Date(data.timestamp) : null;
  const countries = groupFlows(active, "country", data.locations).sort(
    (a, b) => b.flows.length - a.flows.length,
  );
  const localCount = active.filter(
    (f) => scope(f.remoteAddress) === "local",
  ).length;
  useEffect(() => {
    if (!settings && !inspected) return;
    const previous = document.activeElement as HTMLElement;
    const dialog = document.querySelector<HTMLElement>('[role="dialog"]');
    const focusable = () =>
      Array.from(
        dialog?.querySelectorAll<HTMLElement>(
          "button:not(:disabled),select:not(:disabled),input,a[href]",
        ) || [],
      );
    focusable()[0]?.focus();
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setSettings(false);
        setConnection(null);
      }
      if (e.key === "Tab") {
        const all = focusable(),
          first = all[0],
          last = all.at(-1);
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last?.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first?.focus();
        }
      }
    };
    document.addEventListener("keydown", handler);
    return () => {
      document.removeEventListener("keydown", handler);
      previous?.focus();
    };
  }, [settings, inspected?.id]);
  const toggleLocation = async () => {
    if (!window.watchmen) return;
    try {
      const enabled = await window.watchmen.setLocations(
        !data.locationsEnabled,
      );
      setNotice(
        enabled
          ? "Location lookup enabled and remembered. Results arrive gradually."
          : "Location lookup turned off and remembered.",
      );
    } catch {
      setNotice(
        "The location lookup preference could not be saved. Check the local database permissions.",
      );
    }
  };
  const navigate = (name: string) => {
    setPage(name);
    setSelected(null);
    setConnection(null);
    setSearch("");
    if (name === "Applications") setGroup("app");
    if (name === "Destinations") setGroup("destination");
    if (name === "Locations") setGroup("country");
    if (name === "Connections") setGroup("protocol");
  };
  const exporting = async () => {
    try {
      const r = await window.watchmen?.exportSession();
      setNotice(r?.ok ? "Session exported." : r?.error || "");
    } catch {
      setNotice("Could not export the session. Try another location.");
    }
  };
  return (
    <RuleProvider
      admin={data.admin}
      elevate={async () => {
        if (!(await window.watchmen?.relaunchElevated()))
          setNotice(
            "Administrator access was canceled. Saved rules are still available to view.",
          );
      }}
    >
      <div className="shell">
        <aside className="sidebar">
          <div className="brand">
            <span className="brand-mark">
              <Shield size={23} />
            </span>
            <div>
              WATCHMEN<span>NETWORK OPERATIONS</span>
            </div>
          </div>
          <div className="workspace">
            <span className="device-icon">
              <Monitor size={18} />
            </span>
            <div>
              LOCAL NODE<small>Windows / local</small>
            </div>
            <span className="live-dot" />
          </div>
          <div className="nav-label">OPERATIONS</div>
          <nav>
            {[
              [Activity, "Overview"],
              [Box, "Applications"],
              [Globe2, "Destinations"],
              [LocateFixed, "Locations"],
              [Network, "Connections"],
              [Layers, "Traffic profile"],
              [TriangleAlert, "Changes"],
              [Radio, "Packets"],
              [Shield, "Network rules"],
              [Bot, "AI console"],
            ].map(([Icon, name]: any, index: number) => (
              <button
                key={name}
                aria-label={name}
                className={page === name ? "nav-item active" : "nav-item"}
                onClick={() => navigate(name)}
              >
                <span className="nav-index" aria-hidden="true">
                  {String(index + 1).padStart(2, "0")}
                </span>
                <Icon size={19} />
                <span className="nav-name">{name}</span>
                {name === "Applications" && (
                  <span className="nav-count">{appCount}</span>
                )}
                {name === "AI console" &&
                  (assistantActivity.busy || assistantActivity.pending > 0) && (
                    <span className="nav-count">
                      {assistantActivity.busy
                        ? "RUN"
                        : assistantActivity.pending}
                    </span>
                  )}
                {name === "Changes" && !!data.alertCount && (
                  <span className="change-count">{data.alertCount}</span>
                )}
              </button>
            ))}
          </nav>
          <div className="sidebar-bottom">
            <div className="local-card">
              <div>
                <Shield size={17} /> LOCAL DATA VAULT
              </div>
              <p>
                Traffic profiles stay on this device. External lookups are
                optional.
              </p>
              <span>
                LOCAL FIRST <Check size={13} />
              </span>
            </div>
            <button className="nav-item" onClick={() => setSettings(true)}>
              <Settings2 size={19} />
              Settings & privacy
            </button>
            <div className="version">
              <span className="tiny-logo">w</span> Watchmen{" "}
              <span>v{appVersion}</span>
            </div>
          </div>
        </aside>
        <main
          className={page === "Overview" ? "overview-view" : "focused-view"}
        >
          <header className="topbar">
            <div className="breadcrumbs">
              Console <ChevronRight size={13} />
              <strong>{page}</strong>
            </div>
            <div className="header-right">
              <button
                className="button"
                onClick={() => navigate("AI console")}
                aria-label="Open AI console"
              >
                <Bot size={14} />
                {assistantActivity.busy
                  ? "AI working"
                  : assistantActivity.pending
                    ? `${assistantActivity.pending} AI review${assistantActivity.pending === 1 ? "" : "s"}`
                    : "AI console"}
              </button>
              {!!data.alertCount && (
                <button
                  className="button changes-shortcut"
                  onClick={() => navigate("Changes")}
                >
                  <TriangleAlert size={14} />
                  {data.alertCount}{" "}
                  {data.alertCount === 1 ? "change" : "changes"}
                </button>
              )}
              <button
                className="icon-button"
                aria-label={
                  theme === "dark"
                    ? "Switch to light mode"
                    : "Switch to dark mode"
                }
                onClick={() =>
                  changeTheme(
                    document.documentElement.dataset.theme === "dark"
                      ? "light"
                      : "dark",
                  )
                }
              >
                {document.documentElement.dataset.theme === "dark" ? (
                  <Sun size={17} />
                ) : (
                  <Moon size={17} />
                )}
              </button>
              <span
                className={"connection-status " + (paused ? "is-paused" : "")}
              >
                <i />
                {paused
                  ? "View paused"
                  : data.agentError
                    ? "Collector offline"
                    : latest
                      ? "Live monitoring"
                      : "Connecting"}
              </span>
              <button
                className="icon-button"
                aria-label="Settings"
                onClick={() => setSettings(true)}
              >
                <Settings2 size={17} />
              </button>
            </div>
          </header>
          <section className="telemetry-strip" aria-label="Collector telemetry">
            <span className="telemetry-node">
              <Radio size={12} /> LOCAL / NETWORK
            </span>
            <span>
              <small>ACQUISITION</small>
              <b>
                {!latest
                  ? "CONNECTING"
                  : data.agentError
                    ? "OFFLINE"
                    : data.tracing
                      ? "ETW / DETAILED"
                      : "SOCKET TABLE"}
              </b>
            </span>
            <span>
              <small>SOCKETS</small>
              <b>
                {data.flows.filter((f) => f.active).length.toLocaleString()}
              </b>
            </span>
            <span>
              <small>LAST SAMPLE</small>
              <b>
                {latest
                  ? latest.toLocaleTimeString([], { hour12: false })
                  : "--:--:--"}
              </b>
            </span>
            <span>
              <small>PROFILE DB</small>
              <b>
                {data.profileStatus?.available
                  ? "LOCAL / SQLITE"
                  : data.profileStatus?.error
                    ? "UNAVAILABLE"
                    : "INITIALIZING"}
              </b>
            </span>
          </section>
          <div className="content">
            <div className="page-heading">
              <div>
                <div className="eyebrow">WATCHMEN / NETWORK TELEMETRY</div>
                <h1>
                  {page === "Network rules"
                    ? "Access control"
                    : page === "AI console"
                      ? "AI command console"
                      : page === "Changes"
                        ? "Change analysis"
                        : page === "Packets"
                          ? "Packet inspection"
                          : page === "Traffic profile"
                            ? "Traffic archive"
                            : page === "Overview"
                              ? "Network overview"
                              : page === "Applications"
                                ? "Application traffic"
                                : page === "Destinations"
                                  ? "Destination registry"
                                  : page === "Locations"
                                    ? "Location telemetry"
                                    : "Connection matrix"}
                </h1>
                <p>
                  {page === "Network rules"
                    ? "Block apps, endpoints or regions, and decide which executable can reach the network."
                    : page === "AI console"
                      ? "Live telemetry, public research, and reviewed network tasks through OpenAI or OpenRouter."
                      : page === "Changes"
                        ? "Compare new observations with saved traffic profiles, then ask OpenRouter to explain the evidence."
                        : page === "Packets"
                          ? "Inspect decoded packet headers and readable unencrypted payloads in a short local capture."
                          : page === "Traffic profile"
                            ? "Learn recurring apps, destinations, and services from the history saved on this computer."
                            : page === "Overview"
                              ? "Live transfer rates, application activity, and connection telemetry."
                              : page === "Locations"
                                ? "Explore approximate IP locations. VPNs, proxies, and anycast can affect results."
                                : "Explore live network activity and inspect the connections behind it."}
                </p>
              </div>
              {![
                "Traffic profile",
                "Changes",
                "Packets",
                "Network rules",
                "AI console",
              ].includes(page) && (
                <div className="heading-actions">
                  <button
                    className="button"
                    onClick={() => setShowAI((v) => !v)}
                  >
                    <Sparkles size={15} />
                    AI insights
                  </button>
                  <button className="button" onClick={() => setPaused(!paused)}>
                    {paused ? <Play size={15} /> : <Pause size={15} />}{" "}
                    {paused ? "Resume" : "Pause view"}
                  </button>
                  <button className="button primary" onClick={exporting}>
                    <Download size={15} />
                    Export session
                  </button>
                </div>
              )}
            </div>
            <RuleStatusBanner />
            <UpdateBanner />
            {data.agentError && (
              <div className="banner error">
                <Info size={18} />
                <span>{data.agentError}</span>
              </div>
            )}
            {!window.watchmen && (
              <div className="banner">
                <Info size={18} />
                <span>
                  Desktop preview · Open Watchmen.exe to connect to the Windows
                  collector. No sample traffic is displayed.
                </span>
              </div>
            )}
            {!data.tracing && window.watchmen && (
              <div className="banner">
                <Shield size={17} />
                <span>
                  <strong>Connection monitoring is on.</strong> Run as
                  administrator to measure traffic by app and destination.
                </span>
                <button
                  onClick={async () => {
                    if (!(await window.watchmen?.relaunchElevated()))
                      setNotice(
                        "Administrator access was canceled or unavailable. Connection monitoring is still available.",
                      );
                  }}
                >
                  Enable detailed capture <ArrowRight size={14} />
                </button>
              </div>
            )}
            {paused && (
              <div className="banner">
                <Pause size={16} />
                <span>
                  View frozen at {latest?.toLocaleTimeString()}. The local
                  collector continues capturing; export includes the latest
                  collector snapshot.
                </span>
              </div>
            )}
            {data.traceError && (
              <div className="banner error">
                <Info size={16} />
                Detailed capture unavailable: {data.traceError}
              </div>
            )}
            {data.eventsLost > 0 && (
              <div className="banner error">
                <Info size={16} />
                {data.eventsLost} Windows trace events were lost. Per-app byte
                totals may be incomplete.
              </div>
            )}
            {data.errors.length > 0 && (
              <div className="banner error">
                <Info size={16} />
                {data.errors.join(" · ")}
              </div>
            )}
            {data.profileStatus?.error && (
              <div className="banner error">
                <Database size={16} />
                {data.profileStatus.error}
              </div>
            )}
            {page === "AI console" ? (
              <AIConsole
                preferences={preferences}
                admin={data.admin}
                setup={() => setSettings(true)}
                elevate={async () => {
                  if (!(await window.watchmen?.relaunchElevated()))
                    setNotice(
                      "Administrator access was canceled. The proposed action has not been applied.",
                    );
                }}
                navigate={navigate}
              />
            ) : page === "Network rules" ? (
              <NetworkRules />
            ) : page === "Traffic profile" ? (
              <TrafficProfile />
            ) : page === "Changes" ? (
              <Changes
                preferences={preferences}
                setup={() => setSettings(true)}
                inspect={(address) => {
                  setPacketSearch(address);
                  navigate("Packets");
                }}
              />
            ) : page === "Packets" ? (
              <PacketInspector
                admin={data.admin}
                initialSearch={packetSearch}
                elevate={async () => {
                  if (!(await window.watchmen?.relaunchElevated()))
                    setNotice(
                      "Administrator access was canceled or unavailable. PCAP import is still available.",
                    );
                }}
              />
            ) : (
              <>
                <section className="metrics">
                  <Metric
                    label="Download"
                    value={bytes(rx, true)}
                    sub="Incoming traffic"
                    icon={<ArrowDownLeft size={19} />}
                    color="purple"
                  />
                  <Metric
                    label="Upload"
                    value={bytes(tx, true)}
                    sub="Outgoing traffic"
                    icon={<ArrowUpRight size={19} />}
                    color="teal"
                  />
                  <Metric
                    label="Active applications"
                    value={String(appCount)}
                    sub={`${active.length} active connections`}
                    icon={<Box size={19} />}
                    color="blue"
                  />
                  <Metric
                    label="Public destinations"
                    value={String(publicIPs.size)}
                    sub={`${localCount} local connections`}
                    icon={<Globe2 size={19} />}
                    color="orange"
                  />
                </section>
                <section className="charts-grid">
                  <div className="card traffic-card">
                    <div className="card-heading">
                      <div>
                        <h2>
                          <span className="panel-code">01</span> Transfer
                          telemetry{" "}
                          <span className="live-label">
                            <i />
                            {paused ? "PAUSED" : "LIVE"}
                          </span>
                        </h2>
                        <p>Incoming and outgoing, second by second</p>
                      </div>
                      <select
                        aria-label="Chart time window"
                        value={windowSize}
                        onChange={(e) => setWindowSize(Number(e.target.value))}
                      >
                        <option value={60}>Last 60 seconds</option>
                        <option value={300}>Last 5 minutes</option>
                      </select>
                    </div>
                    <div className="chart-toolbar">
                      <div className="legend">
                        <span>
                          <i className="purple-dot" />
                          Download
                        </span>
                        <span>
                          <i className="teal-dot" />
                          Upload
                        </span>
                      </div>
                      <select
                        aria-label="Network interface"
                        value={adapter}
                        onChange={(e) => {
                          setAdapter(e.target.value);
                          setHistory([]);
                        }}
                      >
                        <option value="all">All interfaces</option>
                        {data.adapters.map((a) => (
                          <option key={a.id} value={a.id}>
                            {a.name}
                          </option>
                        ))}
                      </select>
                    </div>
                    <TrafficChart
                      samples={history.slice(-windowSize)}
                      windowSize={windowSize}
                    />
                    <div className="chart-footer">
                      <span>
                        <Radio size={13} />{" "}
                        {data.tracing
                          ? "Per-app capture enabled"
                          : "Adapter totals · per-app capture off"}
                      </span>
                      <span title="Summing virtual and physical interfaces can count VPN traffic twice. Select one interface for its own rate.">
                        {adapter === "all"
                          ? "All interfaces may include VPN overlap"
                          : currentAdapter?.description}
                        <Info size={12} />
                      </span>
                    </div>
                  </div>
                  <div className="card reach-card">
                    <div className="card-heading">
                      <div>
                        <h2>
                          <span className="panel-code">02</span> Location
                          resolver
                        </h2>
                        <p>Remote destination geography</p>
                      </div>
                      <Globe2 size={19} />
                    </div>
                    <div className="orbit">
                      <div className="orbit-ring r1" />
                      <div className="orbit-ring r2" />
                      <div className="orbit-cross" />
                      <div className="orbit-core">
                        <Globe2 size={43} />
                      </div>
                    </div>
                    <div className="radar-caption">
                      {data.locationsEnabled
                        ? "LOOKUP ENABLED"
                        : "RESOLVER STANDBY"}
                    </div>
                    {data.locationsEnabled ? (
                      <>
                        <div className="reach-number">
                          {
                            countries.filter(
                              (c) =>
                                ![
                                  "Unresolved",
                                  "Listening endpoints",
                                  "Local network",
                                  "Lookup unavailable",
                                ].includes(c.name),
                            ).length
                          }
                          <span>countries resolved</span>
                        </div>
                        <div className="country-chips">
                          {countries.slice(0, 3).map((c) => (
                            <button
                              key={c.id}
                              onClick={() => {
                                navigate("Locations");
                                setSearch(
                                  c.name === "Unresolved" ? "" : c.name,
                                );
                              }}
                            >
                              {c.name}
                              <b>{c.flows.length}</b>
                            </button>
                          ))}
                        </div>
                      </>
                    ) : (
                      <>
                        <h3>Location lookup disabled</h3>
                        <p>
                          Resolve approximate countries, cities,
                          <br />
                          and network owners.
                        </p>
                        <button
                          className="text-button"
                          onClick={() => setSettings(true)}
                        >
                          Set up IP locations <ArrowRight size={15} />
                        </button>
                      </>
                    )}
                  </div>
                </section>
                {showAI && (
                  <AIInsights
                    flows={chosen?.flows || flows}
                    title={chosen ? chosen.name : "Current view"}
                    preferences={preferences}
                    setup={() => setSettings(true)}
                    close={() => setShowAI(false)}
                  />
                )}
                <section className="card activity-card">
                  <div className="card-heading">
                    <div>
                      <h2>
                        <span className="panel-code">
                          {page === "Overview" ? "03" : "DATA"}
                        </span>
                        {page === "Overview" ? "Connection registry" : page}{" "}
                        <span className="count-pill">{groups.length}</span>
                      </h2>
                      <p>Click a row to explore its connections.</p>
                    </div>
                    <div className="group-switch" aria-label="Group traffic">
                      {(
                        [
                          "app",
                          "destination",
                          "country",
                          "protocol",
                        ] as GroupBy[]
                      ).map((g) => (
                        <button
                          className={group === g ? "selected" : ""}
                          key={g}
                          onClick={() => {
                            setGroup(g);
                            setSelected(null);
                          }}
                        >
                          {g === "app"
                            ? "Applications"
                            : g === "destination"
                              ? "Destinations"
                              : g === "country"
                                ? "Countries"
                                : "Protocols"}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div className="filter-bar">
                    <div className="search">
                      <Search size={16} />
                      <input
                        aria-label="Search traffic"
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder="Search apps, IPs, ports, or countries…"
                      />
                      {search && (
                        <button
                          aria-label="Clear search"
                          onClick={() => setSearch("")}
                        >
                          <X size={14} />
                        </button>
                      )}
                    </div>
                    <select
                      aria-label="Network scope"
                      value={filter}
                      onChange={(e) => setFilter(e.target.value)}
                    >
                      <option value="all">All networks</option>
                      <option value="internet">Internet</option>
                      <option value="local">Local network</option>
                      <option value="listener">Listening sockets</option>
                    </select>
                    <select
                      aria-label="Traffic direction"
                      value={direction}
                      onChange={(e) => setDirection(e.target.value)}
                      disabled={!data.tracing}
                      title={
                        !data.tracing
                          ? "Detailed capture is required for byte-based direction filters"
                          : ""
                      }
                    >
                      <option value="both">Both directions</option>
                      <option value="in">Received data</option>
                      <option value="out">Sent data</option>
                    </select>
                    <select
                      aria-label="Connection activity"
                      value={lifecycle}
                      onChange={(e) => setLifecycle(e.target.value)}
                    >
                      <option value="active">Active now</option>
                      <option value="connected">Session connections</option>
                      <option value="all">All session sockets</option>
                    </select>
                  </div>
                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>
                            <button onClick={() => setSort("name")}>
                              {group === "app"
                                ? "APPLICATION"
                                : group === "destination"
                                  ? "DESTINATION"
                                  : group === "country"
                                    ? "COUNTRY"
                                    : "PROTOCOL"}
                              {sort === "name" && <ChevronDown size={12} />}
                            </button>
                          </th>
                          <th>
                            <button onClick={() => setSort("connections")}>
                              CONNECTIONS
                              {sort === "connections" && (
                                <ChevronDown size={12} />
                              )}
                            </button>
                          </th>
                          <th>
                            <button onClick={() => setSort("download")}>
                              <ArrowDown size={12} /> DOWNLOAD
                            </button>
                          </th>
                          <th>
                            <button onClick={() => setSort("upload")}>
                              <ArrowUp size={12} /> UPLOAD
                            </button>
                          </th>
                          <th>
                            <button onClick={() => setSort("total")}>
                              SESSION DATA
                            </button>
                          </th>
                          <th>ACCESS</th>
                          <th />
                        </tr>
                      </thead>
                      <tbody>
                        {groups.slice(0, 200).map((g) => (
                          <React.Fragment key={g.id}>
                            <tr
                              {...rowAI(
                                group === "app" ? "application" : group,
                                g.name,
                                {
                                  ...(group === "app"
                                    ? { app: g.name }
                                    : group === "country"
                                      ? { country: g.name }
                                      : group === "protocol"
                                        ? { protocol: g.name }
                                        : {
                                            scope: scope(
                                              g.flows[0]?.remoteAddress || "",
                                            ),
                                            country:
                                              data.locations[
                                                g.flows[0]?.remoteAddress
                                              ]?.country || "Unresolved",
                                            networkOwner:
                                              data.locations[
                                                g.flows[0]?.remoteAddress
                                              ]?.org || "Unknown",
                                          }),
                                  connections: g.flows.length,
                                  applications: new Set(
                                    g.flows.map((f) => f.app),
                                  ).size,
                                  measured: data.tracing,
                                  received: data.tracing ? g.received : null,
                                  sent: data.tracing ? g.sent : null,
                                  downloadRate: data.tracing ? g.rxRate : null,
                                  uploadRate: data.tracing ? g.txRate : null,
                                },
                              )}
                              aria-expanded={selected === g.id}
                              className={
                                selected === g.id ? "selected-row" : ""
                              }
                              onClick={() => {
                                setSelected(selected === g.id ? null : g.id);
                                setConnection(null);
                              }}
                              tabIndex={0}
                              onKeyDown={(e) => {
                                if (e.key === "Enter" || e.key === " ") {
                                  e.preventDefault();
                                  setSelected(selected === g.id ? null : g.id);
                                  setConnection(null);
                                }
                              }}
                              aria-label={`Connections for ${g.name}`}
                            >
                              <td>
                                <div className="app-cell">
                                  <span
                                    className={
                                      "app-avatar color-" + (hash(g.name) % 6)
                                    }
                                  >
                                    {group === "app" ? (
                                      g.name.slice(0, 2).toUpperCase()
                                    ) : group === "country" ? (
                                      <Globe2 size={18} />
                                    ) : group === "protocol" ? (
                                      <Network size={18} />
                                    ) : (
                                      <ArrowUpRight size={18} />
                                    )}
                                  </span>
                                  <div>
                                    <strong>{g.name}</strong>
                                    <small>{g.subtitle}</small>
                                  </div>
                                </div>
                              </td>
                              <td>
                                <div className="connections-cell">
                                  <b>{g.flows.length}</b>
                                  <div className="mini-track">
                                    <span
                                      style={{
                                        width:
                                          Math.max(
                                            3,
                                            (g.flows.length /
                                              Math.max(
                                                1,
                                                ...groups.map(
                                                  (r) => r.flows.length,
                                                ),
                                              )) *
                                              100,
                                          ) + "%",
                                      }}
                                    />
                                  </div>
                                </div>
                              </td>
                              <td className="numeric purple-text">
                                {data.tracing ? (
                                  bytes(g.rxRate, true)
                                ) : (
                                  <span className="unavailable">—</span>
                                )}
                              </td>
                              <td className="numeric teal-text">
                                {data.tracing ? (
                                  bytes(g.txRate, true)
                                ) : (
                                  <span className="unavailable">—</span>
                                )}
                              </td>
                              <td className="numeric">
                                {data.tracing ? (
                                  bytes(g.received + g.sent)
                                ) : (
                                  <span className="unavailable">
                                    Capture off
                                  </span>
                                )}
                              </td>
                              <td>
                                {group !== "protocol" && g.flows[0] && (
                                  <RuleActions
                                    flow={g.flows[0]}
                                    kind={
                                      group === "app"
                                        ? "app"
                                        : group === "destination"
                                          ? "destination"
                                          : "region"
                                    }
                                    country={
                                      group === "country"
                                        ? data.locations[
                                            g.flows[0].remoteAddress
                                          ]?.code || g.name
                                        : undefined
                                    }
                                  />
                                )}
                              </td>
                              <td>
                                {selected === g.id ? (
                                  <ChevronDown size={16} />
                                ) : (
                                  <ChevronRight size={16} />
                                )}
                              </td>
                            </tr>
                            {selected === g.id && (
                              <tr className="connection-details-row">
                                <td colSpan={7}>
                                  <ConnectionTable
                                    group={g}
                                    tracing={data.tracing}
                                    locations={data.locations}
                                    inspect={setConnection}
                                  />
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        ))}
                      </tbody>
                    </table>
                    {!groups.length && (
                      <div className="empty">
                        <span>
                          <Search size={25} />
                        </span>
                        <h3>
                          {latest
                            ? "No connections match this view."
                            : "Waiting for your first snapshot."}
                        </h3>
                        <p>
                          {latest
                            ? "Try another search or choose All session sockets."
                            : "The Windows collector will populate this view automatically."}
                        </p>
                        {latest && (
                          <button
                            className="button"
                            onClick={() => {
                              setSearch("");
                              setFilter("all");
                              setLifecycle("all");
                              setDirection("both");
                            }}
                          >
                            Reset filters
                          </button>
                        )}
                      </div>
                    )}
                  </div>
                  <div className="table-footer">
                    <span>
                      Showing {Math.min(groups.length, 200)} of {groups.length}{" "}
                      groups · {flows.length} sockets
                    </span>
                    <span>
                      <Clock size={12} />{" "}
                      {latest
                        ? `Updated ${latest.toLocaleTimeString()}`
                        : "Waiting for collector"}
                      {paused ? " · paused" : ""}
                    </span>
                  </div>
                </section>
                <footer className="page-footer">
                  <span>
                    <Shield size={13} /> Local profiles. Packet capture is on
                    demand.
                  </span>
                  <span>
                    {data.locationsEnabled
                      ? `ipwho.is · ${data.locationStatus}`
                      : "IP location lookup is off"}
                    {data.evictedFlows > 0
                      ? ` · ${data.evictedFlows} old flows evicted`
                      : ""}
                  </span>
                </footer>
              </>
            )}
          </div>
        </main>
        {inspected && (
          <Inspector
            flow={inspected}
            tracing={data.tracing}
            locations={data.locations}
            close={() => setConnection(null)}
            notify={setNotice}
          />
        )}
        {settings && (
          <div className="modal-backdrop" onClick={() => setSettings(false)}>
            <section
              className="modal"
              role="dialog"
              aria-modal="true"
              aria-label="Settings and privacy"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="modal-title">
                <span className="settings-symbol">
                  <Settings2 size={23} />
                </span>
                <button
                  className="icon-button"
                  aria-label="Close settings"
                  onClick={() => setSettings(false)}
                >
                  <X size={20} />
                </button>
              </div>
              <h2>System configuration</h2>
              <p>Appearance, updates, credentials, and capture preferences.</p>
              <div className="appearance-setting">
                <strong>Appearance</strong>
                <div className="theme-switch">
                  {(["system", "light", "dark"] as const).map((value) => (
                    <button
                      key={value}
                      aria-pressed={theme === value}
                      onClick={() => changeTheme(value)}
                    >
                      {value === "system" ? (
                        <Monitor size={14} />
                      ) : value === "light" ? (
                        <Sun size={14} />
                      ) : (
                        <Moon size={14} />
                      )}{" "}
                      {value[0].toUpperCase() + value.slice(1)}
                    </button>
                  ))}
                </div>
              </div>
              <UpdateSettings />
              <AISettings
                preferences={preferences}
                update={setPreferences}
                notify={setNotice}
              />
              <div className="setting-row">
                <div>
                  <strong>IP location lookup</strong>
                  <p>
                    Send public destination IPs to <b>ipwho.is</b> over HTTPS to
                    resolve approximate city, country, and network owner. Your
                    local IPs and packet contents are never submitted. One
                    request per second; this choice is saved for future
                    launches.
                  </p>
                </div>
                <button
                  aria-label="IP location lookup"
                  aria-pressed={data.locationsEnabled}
                  className={"toggle " + (data.locationsEnabled ? "on" : "")}
                  onClick={toggleLocation}
                >
                  <span />
                </button>
              </div>
              <div className="setting-row">
                <div>
                  <strong>Detailed traffic capture</strong>
                  <p>
                    {data.tracing
                      ? "Windows ETW is measuring TCP and UDP bytes by process, including IPv4 and IPv6."
                      : "Windows requires administrator access for per-process TCP and UDP byte measurements. Adapter totals and socket lists work without elevation."}
                  </p>
                </div>
                <span className="badge">
                  {data.tracing ? "Enabled" : "Off"}
                </span>
              </div>
              <div className="privacy-note">
                <Shield size={19} />
                <p>
                  Traffic metadata is saved locally to build your profile across
                  launches. Live charts stay in memory. Export saves the current
                  session to a file you choose. Location lookup starts off until
                  you enable it; your saved choice is then reused. Cached
                  locations remain in your local profile.
                </p>
              </div>
              <small>
                Rates reflect observed transport events, not decrypted content.
                Listening UDP sockets do not reveal peers until detailed capture
                sees a datagram. VPN traffic can appear on multiple adapters.
              </small>
              <button
                className="button primary full"
                onClick={() => setSettings(false)}
              >
                Back to my network
              </button>
            </section>
          </div>
        )}
        {notice && (
          <div className="toast" role="status">
            <Info size={17} />
            {notice}
            <button aria-label="Dismiss message" onClick={() => setNotice("")}>
              <X size={15} />
            </button>
          </div>
        )}
      </div>
    </RuleProvider>
  );
}
function hash(s: string) {
  return [...s].reduce((n, c) => (n * 31 + c.charCodeAt(0)) >>> 0, 0);
}
function Metric({
  label,
  value,
  sub,
  icon,
  color,
}: {
  label: string;
  value: string;
  sub: string;
  icon: React.ReactNode;
  color: string;
}) {
  return (
    <div className="card metric">
      <div className="metric-top">
        <span>{label}</span>
        <span className={"metric-icon " + color}>{icon}</span>
      </div>
      <div className="metric-value">{value}</div>
      <div className="metric-sub">{sub}</div>
    </div>
  );
}
function TrafficChart({
  samples,
  windowSize,
}: {
  samples: Sample[];
  windowSize: number;
}) {
  const newest = samples.length
    ? new Date(samples.at(-1)!.time).getTime()
    : Date.now();
  samples = samples.filter(
    (s) => new Date(s.time).getTime() > newest - windowSize * 1000,
  );
  const max = Math.max(1024, ...samples.flatMap((s) => [s.rx, s.tx])) * 1.15;
  const width = 760,
    height = 155;
  const x = (s: Sample) =>
    Math.max(
      0,
      1 - (newest - new Date(s.time).getTime()) / (windowSize * 1000),
    ) * width;
  const line = (key: "rx" | "tx") =>
    samples
      .map(
        (s, i) =>
          `${i === 0 || new Date(s.time).getTime() - new Date(samples[i - 1].time).getTime() > 3000 ? "M" : "L"} ${x(s)} ${height - (s[key] / max) * height}`,
      )
      .join(" ");
  const fill = (key: "rx" | "tx") =>
    samples.length
      ? `${line(key)} L ${width} ${height} L ${x(samples[0])} ${height} Z`
      : "";
  return (
    <div className="traffic-chart">
      <div className="y-labels">
        {[1, 0.5, 0].map((v) => (
          <span key={v}>{bytes(max * v, true)}</span>
        ))}
      </div>
      <div className="chart-plot">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          preserveAspectRatio="none"
          role="img"
          aria-label="Measured download and upload rates"
        >
          <defs>
            <linearGradient id="rxFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--accent)" stopOpacity=".2" />
              <stop offset="100%" stopColor="var(--accent)" stopOpacity=".01" />
            </linearGradient>
          </defs>
          {[0, 0.5, 1].map((y) => (
            <line
              key={y}
              x1="0"
              x2={width}
              y1={height * y}
              y2={height * y}
              stroke="var(--chart-grid, #e9e9f0)"
              strokeDasharray="4 5"
            />
          ))}
          <path d={fill("rx")} fill="url(#rxFill)" />
          <path
            d={line("rx")}
            fill="none"
            stroke="var(--accent)"
            strokeWidth="2.5"
            vectorEffect="non-scaling-stroke"
          />
          <path
            d={line("tx")}
            fill="none"
            stroke="var(--success)"
            strokeWidth="2"
            vectorEffect="non-scaling-stroke"
          />
        </svg>
        {samples.length < 2 && (
          <span className="chart-waiting">Collecting live measurements…</span>
        )}
        <div className="x-labels">
          <span>
            −{windowSize < 120 ? windowSize + "s" : windowSize / 60 + "m"}
          </span>
          <span>−{windowSize / 2}s</span>
          <span>Now</span>
        </div>
      </div>
    </div>
  );
}
function ConnectionTable({
  group: g,
  tracing,
  locations,
  inspect,
}: {
  group: Group;
  tracing: boolean;
  locations: Snapshot["locations"];
  inspect: (id: string) => void;
}) {
  const [query, setQuery] = useState(""),
    [sort, setSort] = useState("destination"),
    [page, setPage] = useState(0);
  const rows = useMemo(
    () =>
      g.flows
        .filter((f) =>
          [
            f.app,
            f.pid,
            f.protocol,
            f.state,
            f.localAddress,
            f.localPort,
            f.remoteAddress,
            f.remotePort,
            locations[f.remoteAddress]?.country,
          ]
            .join(" ")
            .toLowerCase()
            .includes(query.toLowerCase()),
        )
        .sort((a, b) =>
          sort === "download"
            ? b.rxRate - a.rxRate
            : sort === "upload"
              ? b.txRate - a.txRate
              : sort === "pid"
                ? a.pid - b.pid
                : sort === "state"
                  ? a.state.localeCompare(b.state)
                  : a.remoteAddress.localeCompare(b.remoteAddress) ||
                    a.remotePort - b.remotePort,
        ),
    [g.flows, query, sort, locations],
  );
  const current = Math.min(page, Math.max(0, Math.ceil(rows.length / 25) - 1));
  return (
    <section
      className="nested-connections"
      aria-label={`Connections in ${g.name}`}
    >
      <div className="nested-heading">
        <div>
          <Network size={16} />
          <strong>Connections in {g.name}</strong>
          <span className="count-pill">{rows.length}</span>
        </div>
        <div className="search">
          <Search size={14} />
          <input
            aria-label="Search connections"
            placeholder="Filter IPs, ports, process IDs…"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setPage(0);
            }}
          />
        </div>
      </div>
      <div className="nested-table-scroll">
        <table aria-label="Individual connections">
          <thead>
            <tr>
              <th>PROTOCOL / PID</th>
              <th>
                <button onClick={() => setSort("destination")}>
                  DESTINATION <ChevronDown size={11} />
                </button>
              </th>
              <th>LOCAL ENDPOINT</th>
              <th>
                <button onClick={() => setSort("state")}>STATE</button>
              </th>
              <th>
                <button onClick={() => setSort("download")}>DOWNLOAD</button>
              </th>
              <th>
                <button onClick={() => setSort("upload")}>UPLOAD</button>
              </th>
              <th>ACCESS</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.slice(current * 25, current * 25 + 25).map((f) => (
              <tr
                key={f.id}
                {...rowAI(
                  "connection",
                  `${f.app} · ${f.remoteAddress}:${f.remotePort}`,
                  {
                    app: f.app,
                    protocol: f.protocol,
                    remotePort: f.remotePort,
                    state: f.state,
                    active: f.active,
                    scope: scope(f.remoteAddress),
                    country:
                      locations[f.remoteAddress]?.country || "Unresolved",
                    networkOwner: locations[f.remoteAddress]?.org || "Unknown",
                    measured: tracing,
                    received: tracing ? f.received : null,
                    sent: tracing ? f.sent : null,
                  },
                )}
                tabIndex={0}
                aria-label={`Inspect connection ${f.remoteAddress} port ${f.remotePort} PID ${f.pid}`}
                onClick={() => inspect(f.id)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    inspect(f.id);
                  }
                }}
              >
                <td>
                  <strong>{f.protocol}</strong>
                  <small>
                    PID {f.pid} · {f.app}
                  </small>
                </td>
                <td>
                  <strong className="endpoint-ip">
                    {f.remoteAddress}
                    {f.remotePort ? `:${f.remotePort}` : ""}
                  </strong>
                  <small>
                    {locations[f.remoteAddress]?.country ||
                      scope(f.remoteAddress)}
                  </small>
                </td>
                <td className="endpoint-ip">
                  {f.localAddress}:{f.localPort}
                </td>
                <td>
                  <span
                    className={
                      "state-chip " +
                      (f.state === "Established" ? "established" : "")
                    }
                  >
                    {f.state}
                  </span>
                </td>
                <td className="numeric purple-text">
                  {tracing ? bytes(f.rxRate, true) : "—"}
                </td>
                <td className="numeric teal-text">
                  {tracing ? bytes(f.txRate, true) : "—"}
                </td>
                <td>
                  <RuleActions
                    flow={f}
                    kind={
                      f.processPath?.toLowerCase().endsWith(".exe") &&
                      f.remotePort > 0
                        ? "connection"
                        : "destination"
                    }
                  />
                </td>
                <td>
                  <ChevronRight size={14} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!rows.length && (
          <div className="empty">No connections match this filter.</div>
        )}
      </div>
      <div className="nested-footer">
        <span>
          {rows.length ? current * 25 + 1 : 0}–
          {Math.min((current + 1) * 25, rows.length)} of {rows.length}{" "}
          connections
        </span>
        <div>
          <button
            className="button"
            disabled={current === 0}
            onClick={() => setPage(current - 1)}
          >
            Previous
          </button>
          <button
            className="button"
            disabled={(current + 1) * 25 >= rows.length}
            onClick={() => setPage(current + 1)}
          >
            Next
          </button>
        </div>
      </div>
    </section>
  );
}
function Inspector({
  flow: f,
  tracing,
  locations,
  close,
  notify,
}: {
  flow: Flow;
  tracing: boolean;
  locations: Snapshot["locations"];
  close: () => void;
  notify: (s: string) => void;
}) {
  useEffect(() => {
    const handle = (e: KeyboardEvent) => {
      if (e.key === "Escape") close();
    };
    document.addEventListener("keydown", handle);
    return () => document.removeEventListener("keydown", handle);
  }, [close]);
  return (
    <div className="inspector-backdrop" onClick={close}>
      <aside
        className="inspector"
        role="dialog"
        aria-modal="true"
        aria-label="Connection inspector"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="inspector-heading">
          <span>CONNECTION INSPECTOR</span>
          <button
            className="icon-button"
            aria-label="Close inspector"
            onClick={close}
          >
            <X size={21} />
          </button>
        </div>
        <span className={"app-avatar large color-" + (hash(f.app) % 6)}>
          {f.app.slice(0, 2).toUpperCase()}
        </span>
        <h2>{f.app}</h2>
        <p>
          {f.protocol} · PID {f.pid} · {f.state}
        </p>
        <div className="inspector-stats">
          <div>
            <small>Download</small>
            <strong>{tracing ? bytes(f.rxRate, true) : "—"}</strong>
          </div>
          <div>
            <small>Upload</small>
            <strong>{tracing ? bytes(f.txRate, true) : "—"}</strong>
          </div>
          <div>
            <small>Session data</small>
            <strong>{tracing ? bytes(f.received + f.sent) : "—"}</strong>
          </div>
        </div>
        {f && (
          <>
            <div className="endpoint-diagram">
              <div>
                <Monitor size={20} />
                <strong>{f.app}</strong>
                <small>
                  {f.localAddress}:{f.localPort}
                </small>
              </div>
              <div className="endpoint-arrow">
                <ArrowRight size={23} />
                <small>{f.protocol}</small>
              </div>
              <div>
                <Globe2 size={20} />
                <strong>
                  {scope(f.remoteAddress) === "listener"
                    ? "Listening"
                    : locations[f.remoteAddress]?.country || "Destination"}
                </strong>
                <small>
                  {f.remoteAddress}:{f.remotePort || "*"}
                </small>
              </div>
            </div>
            <dl>
              {[
                ["Process ID", f.pid],
                ["State", f.state],
                ["Protocol", f.protocol],
                ["Scope", scope(f.remoteAddress)],
                ["Remote IP", f.remoteAddress],
                ["Remote port", f.remotePort || "Any"],
                ["Local address", f.localAddress],
                ["Local port", f.localPort],
                [
                  "Country",
                  locations[f.remoteAddress]?.country || "Unresolved",
                ],
                ["City", locations[f.remoteAddress]?.city || "Unresolved"],
                [
                  "Network owner",
                  locations[f.remoteAddress]?.org || "Unresolved",
                ],
                ["Received", tracing ? bytes(f.received) : "Capture off"],
                ["Sent", tracing ? bytes(f.sent) : "Capture off"],
                ["First observed", new Date(f.firstSeen).toLocaleTimeString()],
              ].map(([key, value]) => (
                <React.Fragment key={key}>
                  <dt>{key}</dt>
                  <dd>{value}</dd>
                </React.Fragment>
              ))}
            </dl>
            <h3>Executable</h3>
            <div className="executable">
              {f.processPath || "Path unavailable for this process."}
            </div>
            <button
              className="button full"
              disabled={!f.processPath}
              onClick={async () => {
                if (!(await window.watchmen?.openPath(f.pid)))
                  notify("The executable path is unavailable.");
              }}
            >
              <FolderOpen size={16} />
              Show in File Explorer
            </button>
          </>
        )}
        <div className="inspector-note">
          <Info size={15} />
          <span>
            Connection endpoints don’t indicate which side initiated a
            connection. Download and upload refer to observed byte direction.
          </span>
        </div>
      </aside>
    </div>
  );
}
createRoot(document.getElementById("root")!).render(
  <>
    <App />
    <RowOverviewUI />
  </>,
);
