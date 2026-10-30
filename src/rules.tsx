import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import {
  Ban,
  Shield,
  ShieldCheck,
  Globe2,
  FolderOpen,
  RefreshCw,
  Unlock,
  Trash2,
  X,
  LoaderCircle,
  Info,
  Search,
} from "lucide-react";
import type { Flow } from "./model";
export type NetworkRule = {
  id: string;
  kind:
    "app" | "connection" | "destination" | "region" | "onlyRegion" | "onlyApp";
  label: string;
  appPath: string;
  address: string;
  protocol: string;
  port: number;
  countries: string[];
  sourceMonth: string;
  rangeCount: number;
  nativeRuleCount: number;
  enabled: boolean;
  partial: boolean;
  createdAt: string;
  allowLocalNetwork?: boolean;
  allowUnknown?: boolean;
};
export type RuleJob = {
  id: string;
  status: string;
  stage: string;
  message: string;
  completed: number;
  total: number;
  canCancel: boolean;
  startedAt: string;
  lastAdvancedAt: string;
  endedAt?: string;
};
export type RuleState = {
  rules: NetworkRule[];
  admin: boolean;
  profiles: { profile: number; enabled: boolean }[];
  isolationVerified: boolean;
  verificationError: string | null;
  updatedAt: string | null;
  error: string | null;
  busy: boolean;
  phase: string;
  job?: RuleJob | null;
};
export type RulePreview = { id: string; rule: NetworkRule; expires: number };
export type RuleCatalog = {
  countries: { code: string; name: string; region: string }[];
  regions: { name: string; countries: string[] }[];
  attribution: string;
  sourceUrl: string;
};
export type RuleInput = {
  kind: string;
  flowId?: string;
  countries?: string[];
  allowLocalNetwork?: boolean;
  allowUnknown?: boolean;
};
type Context = {
  state: RuleState | null;
  catalog: RuleCatalog | null;
  admin: boolean;
  busy: boolean;
  preview: (input: RuleInput) => void;
  pick: (only: boolean) => void;
  toggle: (rule: NetworkRule) => void;
  forget: (id: string) => void;
  refresh: () => void;
  unblockAll: () => void;
  elevate: () => void;
};
const RulesContext = createContext<Context | null>(null);
const useRules = () => {
  const value = useContext(RulesContext);
  if (!value) throw new Error("Network rules are unavailable.");
  return value;
};
export function RuleProvider({
  children,
  admin,
  elevate,
}: {
  children: ReactNode;
  admin: boolean;
  elevate: () => void;
}) {
  const [state, setState] = useState<RuleState | null>(null),
    [catalog, setCatalog] = useState<RuleCatalog | null>(null),
    [review, setReview] = useState<RulePreview | null>(null),
    [minimized, setMinimized] = useState(false),
    [dismissedTask, setDismissedTask] = useState(""),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [acknowledged, setAcknowledged] = useState(false),
    [message, setMessage] = useState("");
  useEffect(() => {
    let active = true;
    const poll = async () => {
      const r = await window.watchmen?.firewallStatus();
      if (active && r) {
        if (r.ok) setState(r.value);
        else setError(r.error);
      }
    };
    poll();
    window.watchmen?.firewallCatalog().then((r) => {
      if (active && r.ok) setCatalog(r.value);
    });
    const timer = setInterval(poll, 500);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);
  useEffect(() => {
    if (!message) return;
    const timer = setTimeout(() => setMessage(""), 6000);
    return () => clearTimeout(timer);
  }, [message]);
  useEffect(() => {
    if (!review) return;
    const previous = document.activeElement as HTMLElement | null;
    const dialog = document.querySelector<HTMLElement>(".policy-dialog");
    dialog
      ?.querySelector<HTMLElement>(".policy-dialog-actions button")
      ?.focus();
    return () => previous?.focus();
  }, [review?.id]);
  const run = async (
    action: () => Promise<any> | undefined,
    success: string,
  ) => {
    setBusy(true);
    setError("");
    try {
      const r = await action();
      if (r) {
        if (r.ok) {
          setState(r.value);
          setMessage(
            r.value?.job?.status === "needsVerification"
              ? r.value.job.message
              : success,
          );
          return true;
        }
        setError(r.error);
      }
      return false;
    } finally {
      setBusy(false);
    }
  };
  const open = (r: any) => {
    if (r?.ok && r.value) {
      setReview(r.value);
      setMinimized(false);
      setAcknowledged(false);
      setError("");
    } else if (r && !r.ok) setError(r.error);
  };
  const context: Context = {
    state,
    catalog,
    admin,
    busy: busy || !!state?.busy,
    preview: async (input) => {
      setBusy(true);
      try {
        open(await window.watchmen?.firewallPreview(input));
      } finally {
        setBusy(false);
      }
    },
    pick: async (only) => open(await window.watchmen?.firewallPickApp(only)),
    toggle: (rule) =>
      run(
        () => window.watchmen?.firewallToggle(rule.id, !rule.enabled),
        rule.enabled
          ? "Rule unblocked. Other matching blocks still apply."
          : "Persistent block enabled.",
      ),
    forget: (id) =>
      run(() => window.watchmen?.firewallForget(id), "Saved rule removed."),
    refresh: () =>
      run(
        () => window.watchmen?.firewallStatus(true),
        "Network rules refreshed.",
      ),
    unblockAll: () =>
      run(
        () => window.watchmen?.firewallUnblockAll(),
        "All Watchmen restrictions are off.",
      ),
    elevate,
  };
  return (
    <RulesContext.Provider value={context}>
      {children}
      {message && (
        <div className="policy-toast" role="status">
          <ShieldCheck size={17} />
          {message}
        </div>
      )}
      {error && (!review || minimized) && (
        <div className="policy-toast error" role="alert">
          <Info size={17} />
          {error}
          <button
            className="icon-button"
            aria-label="Dismiss rule error"
            onClick={() => setError("")}
          >
            <X size={15} />
          </button>
        </div>
      )}
      {(state?.busy || (state?.job && state.job.id !== dismissedTask)) &&
        (!review || minimized) && (
          <aside className="policy-task card" aria-label="Network rule task">
            <div className="policy-task-heading">
              <strong>
                {state?.busy ? "Network rule task" : "Rule task finished"}
              </strong>
              {!state?.busy && (
                <button
                  className="icon-button"
                  aria-label="Dismiss completed task"
                  onClick={() => setDismissedTask(state?.job?.id || "")}
                >
                  <X size={16} />
                </button>
              )}
            </div>
            <TaskProgress state={state} />
            <div className="policy-task-actions">
              {review && (
                <button className="button" onClick={() => setMinimized(false)}>
                  Show task
                </button>
              )}
              {state?.busy && state.job?.canCancel && (
                <button
                  className="button"
                  onClick={async () => {
                    const r = await window.watchmen?.firewallCancel();
                    if (r?.ok) setState(r.value);
                    else if (r) setError(r.error);
                  }}
                >
                  Cancel task
                </button>
              )}
            </div>
          </aside>
        )}
      {review && !minimized && (
        <div
          className="modal-backdrop policy-backdrop"
          onClick={() => {
            if (busy || state?.busy) setMinimized(true);
            else setReview(null);
          }}
        >
          <section
            className="policy-dialog card"
            role="dialog"
            aria-modal="true"
            aria-labelledby="policy-review-title"
            onClick={(e) => e.stopPropagation()}
            onKeyDown={(e) => {
              if (e.key === "Escape") {
                e.preventDefault();
                e.stopPropagation();
                if (busy || state?.busy) setMinimized(true);
                else setReview(null);
              }
              if (e.key === "Tab") {
                const items = Array.from(
                  e.currentTarget.querySelectorAll<HTMLElement>(
                    "button:not(:disabled),input:not(:disabled),select:not(:disabled),a[href]",
                  ),
                );
                const first = items[0],
                  last = items[items.length - 1];
                if (e.shiftKey && document.activeElement === first) {
                  e.preventDefault();
                  last?.focus();
                } else if (!e.shiftKey && document.activeElement === last) {
                  e.preventDefault();
                  first?.focus();
                }
              }
            }}
          >
            <div className="card-heading">
              <div>
                <div className="eyebrow">PERSISTENT NETWORK RULE</div>
                <h2 id="policy-review-title">
                  {review.rule.kind === "onlyApp"
                    ? "Allow network access to only this app"
                    : review.rule.kind === "onlyRegion"
                      ? "Allow only selected countries / regions"
                      : review.rule.kind === "region"
                        ? "Block selected regions"
                        : review.rule.kind === "app"
                          ? "Block this application"
                          : review.rule.kind === "connection"
                            ? "Block this endpoint for this app"
                            : "Block this destination for every app"}
                </h2>
              </div>
              <button
                className="icon-button"
                aria-label={
                  busy || state?.busy
                    ? "Minimize rule task"
                    : "Close rule preview"
                }
                onClick={() =>
                  busy || state?.busy ? setMinimized(true) : setReview(null)
                }
              >
                <X size={18} />
              </button>
            </div>
            <div className="policy-dialog-body">
              <h3>{review.rule.label}</h3>
              <dl className="rule-scope">
                <dt>Application</dt>
                <dd>
                  {review.rule.appPath || "Every application on this computer"}
                </dd>
                {review.rule.address && (
                  <>
                    <dt>Remote endpoint</dt>
                    <dd>
                      {review.rule.address}
                      {review.rule.port
                        ? ` · ${review.rule.protocol}/${review.rule.port}`
                        : ""}
                    </dd>
                  </>
                )}
                {review.rule.countries.length > 0 && (
                  <>
                    <dt>Countries / territories</dt>
                    <dd>
                      {review.rule.countries
                        .map(
                          (code) =>
                            catalog?.countries.find((c) => c.code === code)
                              ?.name || code,
                        )
                        .join(", ")}
                    </dd>
                  </>
                )}
                <dt>Directions</dt>
                <dd>
                  Incoming and outgoing ·{" "}
                  {review.rule.address
                    ? review.rule.address.includes(":")
                      ? "IPv6"
                      : "IPv4"
                    : "IPv4 and IPv6"}
                </dd>
                {["region", "onlyRegion"].includes(review.rule.kind) && (
                  <>
                    <dt>Dataset</dt>
                    <dd>
                      DB-IP {review.rule.sourceMonth} ·{" "}
                      {review.rule.rangeCount.toLocaleString()} IP ranges
                    </dd>
                    <dt>Windows filters</dt>
                    <dd>
                      {review.rule.nativeRuleCount.toLocaleString()} filters,
                      applied together
                    </dd>
                  </>
                )}
                <dt>Persistence</dt>
                <dd>
                  Survives app exit and Windows restart. Unblock from Network
                  rules.
                </dd>
              </dl>
              {review.rule.kind === "region" && (
                <p className="policy-impact">
                  Prepared from this month's DB-IP data. Blocks every
                  destination in these ranges, including unseen IPs. Location is
                  approximate; VPNs, CDNs and routing can affect coverage. Large
                  selections can take several minutes to apply. The rule keeps
                  this snapshot until removed and recreated.
                </p>
              )}
              {review.rule.kind === "onlyRegion" && (
                <>
                  <p className="policy-impact severe">
                    Restricts every app to destinations assigned to the selected
                    countries. Other country destinations are blocked in both
                    directions. Existing blocks still apply, including blocks
                    for selected countries. Location is approximate; VPNs and
                    CDNs can affect coverage. Large selections can take several
                    minutes.
                  </p>
                  <dl className="rule-scope">
                    <dt>Local network</dt>
                    <dd>
                      {review.rule.allowLocalNetwork
                        ? "Exempt: private, loopback, link-local, shared carrier and multicast addresses"
                        : "Restricted too"}
                    </dd>
                    <dt>Unknown public locations</dt>
                    <dd>
                      {review.rule.allowUnknown
                        ? "Allowed when absent from the country dataset or marked unknown"
                        : "Blocked"}
                    </dd>
                  </dl>
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={acknowledged}
                      onChange={(e) => setAcknowledged(e.target.checked)}
                    />
                    I understand that destinations outside this selection will
                    lose access.
                  </label>
                </>
              )}
              {review.rule.kind === "connection" && (
                <p className="policy-impact">
                  Blocks this executable from this remote IP, protocol and port
                  across future connections. Other apps and destinations keep
                  their existing access.
                </p>
              )}
              {review.rule.kind === "app" && (
                <p className="policy-impact">
                  Applies to every process running this executable path,
                  including future launches. Helper executables at other paths
                  need their own rules.
                </p>
              )}
              {review.rule.kind === "onlyApp" && (
                <>
                  <p className="policy-impact severe">
                    Other executables and Windows services will lose network
                    access. Apps relying on system DNS or a separate
                    proxy/helper may stop working. The selected executable
                    remains subject to existing Windows and Watchmen blocks.
                    Watchmen's local controls remain available to turn this mode
                    off.
                  </p>
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={acknowledged}
                      onChange={(e) => setAcknowledged(e.target.checked)}
                    />
                    I understand that other apps and services will lose network
                    access.
                  </label>
                </>
              )}
              {!admin && (
                <div className="banner">
                  <Shield size={17} />
                  <span>
                    Administrator access is required. Restart, then review the
                    rule again.
                  </span>
                </div>
              )}
              {error && (
                <p className="inline-error" role="alert">
                  {error}
                </p>
              )}
              {(busy || state?.busy) && <TaskProgress state={state} />}
              <div className="policy-dialog-actions">
                <button
                  className="button"
                  onClick={() =>
                    busy || state?.busy ? setMinimized(true) : setReview(null)
                  }
                >
                  {busy || state?.busy ? "Minimize task" : "Cancel"}
                </button>
                {admin ? (
                  <button
                    className="button danger"
                    disabled={
                      busy ||
                      state?.busy ||
                      (["onlyApp", "onlyRegion"].includes(review.rule.kind) &&
                        !acknowledged)
                    }
                    onClick={async () => {
                      if (
                        await run(
                          () => window.watchmen?.firewallApply(review.id),
                          review.rule.kind === "onlyApp"
                            ? "Only-app mode enabled."
                            : review.rule.kind === "onlyRegion"
                              ? "Country-only mode enabled."
                              : "Persistent block enabled.",
                        )
                      )
                        setReview(null);
                    }}
                  >
                    {busy || state?.busy ? (
                      <LoaderCircle className="spin" size={15} />
                    ) : (
                      <Ban size={15} />
                    )}{" "}
                    {busy || state?.busy
                      ? state?.phase || "Applying rule…"
                      : review.rule.kind === "onlyApp"
                        ? "Enable only-app mode"
                        : review.rule.kind === "onlyRegion"
                          ? "Enable country-only mode"
                          : "Block now"}
                  </button>
                ) : (
                  <button className="button primary" onClick={elevate}>
                    <Shield size={15} />
                    Restart as administrator
                  </button>
                )}
              </div>
            </div>
          </section>
        </div>
      )}
    </RulesContext.Provider>
  );
}
function TaskProgress({ state }: { state: RuleState | null }) {
  const job = state?.job,
    running = !!state?.busy;
  const stale =
    running && job && Date.now() - Date.parse(job.lastAdvancedAt) > 30000;
  const seconds = job
    ? Math.max(
        0,
        Math.floor(
          (Date.parse(job.endedAt || new Date().toISOString()) -
            Date.parse(job.startedAt)) /
            1000,
        ),
      )
    : 0;
  return (
    <div className="policy-progress" role="status" aria-live="polite">
      <p>
        {running
          ? job?.message || state?.phase || "Preparing network rules…"
          : job?.message}
      </p>
      {running &&
        (job && job.total > 0 ? (
          <progress
            aria-label="Windows filter progress"
            max={job.total}
            value={job.completed}
          />
        ) : (
          <progress aria-label="Windows rule operation in progress" />
        ))}
      {job && (
        <small>
          {running && job.total > 0
            ? `${job.completed.toLocaleString()} / ${job.total.toLocaleString()} filters · `
            : ""}
          {Math.floor(seconds / 60)}m {seconds % 60}s{running ? " elapsed" : ""}
        </small>
      )}
      {running && (
        <small>
          Rules become active together after Windows commits. You can continue
          monitoring.
        </small>
      )}
      {stale && (
        <small className="policy-stall">
          Windows has reported no new completed steps for over 30 seconds. The
          helper is still responding; completion time is unknown.
        </small>
      )}
    </div>
  );
}
export function RuleStatusBanner() {
  const { state, busy, toggle, admin, elevate } = useRules();
  const active = (state?.rules || []).filter(
    (r) => r.enabled && ["onlyApp", "onlyRegion"].includes(r.kind),
  );
  return (
    <>
      {active.map((rule) => (
        <div className="banner isolation-banner" key={rule.id}>
          <ShieldCheck size={18} />
          <span>
            <strong>
              {rule.kind === "onlyRegion"
                ? "Country-only mode"
                : "Only-app mode"}
              : {rule.label}.
            </strong>{" "}
            {rule.kind === "onlyRegion"
              ? "Other destinations are restricted."
              : "Other executables are restricted."}
            {!state?.isolationVerified
              ? " Saved state; Windows verification is unavailable."
              : ""}
          </span>
          <button
            disabled={busy}
            onClick={() => (admin ? toggle(rule) : elevate())}
          >
            {admin
              ? rule.kind === "onlyRegion"
                ? "Turn off country-only mode"
                : "Turn off app isolation"
              : "Restart to unblock"}
            <Unlock size={14} />
          </button>
        </div>
      ))}
    </>
  );
}
export function RuleActions({
  flow,
  kind,
  country,
}: {
  flow: Flow;
  kind: "app" | "connection" | "destination" | "region";
  country?: string;
}) {
  const { state, catalog, busy, preview, toggle, admin } = useRules();
  let code = country;
  if (kind === "region" && !/^[A-Z]{2}$/.test(code || ""))
    code = catalog?.countries.find((c) => c.name === country)?.code;
  const direct = state?.rules.find(
    (r) =>
      r.kind === kind &&
      (kind === "app"
        ? r.appPath.toLowerCase() === flow.processPath.toLowerCase()
        : kind === "connection"
          ? r.appPath.toLowerCase() === flow.processPath.toLowerCase() &&
            r.address === flow.remoteAddress &&
            r.port === flow.remotePort &&
            r.protocol === flow.protocol
          : kind === "destination"
            ? r.address === flow.remoteAddress
            : r.countries.length === 1 && r.countries[0] === code),
  );
  const valid =
    kind === "region"
      ? !!code
      : kind === "app"
        ? !!flow.processPath && flow.processPath.toLowerCase().endsWith(".exe")
        : kind === "connection"
          ? !!flow.processPath &&
            flow.remotePort > 0 &&
            !["*", "0.0.0.0", "::"].includes(flow.remoteAddress)
          : !["*", "0.0.0.0", "::"].includes(flow.remoteAddress);
  const label =
    kind === "app"
      ? "app"
      : kind === "connection"
        ? "connection"
        : kind === "region"
          ? "country"
          : "destination";
  if (!valid) return null;
  return (
    <div
      className="row-rule-actions"
      onClick={(e) => e.stopPropagation()}
      onKeyDown={(e) => e.stopPropagation()}
    >
      <button
        className={
          "button rule-button " + (direct?.enabled ? "is-blocked" : "")
        }
        aria-label={`${direct?.enabled ? "Unblock" : "Block"} ${label} ${kind === "region" ? country : kind === "app" ? flow.app : flow.remoteAddress}`}
        disabled={busy || (!!direct?.enabled && !admin)}
        title={
          direct?.enabled && !admin
            ? "Restart as administrator to unblock this rule."
            : undefined
        }
        onClick={() =>
          direct?.enabled
            ? toggle(direct)
            : preview({
                kind,
                flowId: flow.id,
                ...(code ? { countries: [code] } : {}),
              })
        }
      >
        {direct?.enabled ? <Unlock size={13} /> : <Ban size={13} />}{" "}
        {direct?.enabled ? "Unblock" : "Block"}
      </button>
      {kind === "app" && (
        <button
          className="icon-button only-app-button"
          disabled={busy}
          title="Block all other apps and allow only this executable"
          aria-label={`Allow only ${flow.app}`}
          onClick={() => preview({ kind: "onlyApp", flowId: flow.id })}
        >
          <ShieldCheck size={16} />
        </button>
      )}
    </div>
  );
}
export function NetworkRules() {
  const {
    state,
    catalog,
    admin,
    busy,
    preview,
    pick,
    toggle,
    forget,
    refresh,
    unblockAll,
    elevate,
  } = useRules();
  const [selection, setSelection] = useState<string[]>([]),
    [countrySearch, setCountrySearch] = useState(""),
    [countryMode, setCountryMode] = useState("region"),
    [allowLocalNetwork, setAllowLocalNetwork] = useState(true),
    [allowUnknown, setAllowUnknown] = useState(false),
    [search, setSearch] = useState(""),
    [filter, setFilter] = useState("all");
  const rules = (state?.rules || []).filter(
    (r) =>
      (filter === "all" || (filter === "active" ? r.enabled : !r.enabled)) &&
      [r.label, r.appPath, r.address, ...r.countries]
        .join(" ")
        .toLowerCase()
        .includes(search.toLowerCase()),
  );
  const countryRows = (catalog?.countries || []).filter((c) =>
    [c.name, c.code, c.region]
      .join(" ")
      .toLowerCase()
      .includes(countrySearch.toLowerCase()),
  );
  return (
    <div className="network-rules-view">
      <div className="banner">
        <Shield size={18} />
        <span>
          Rules are enforced by Windows and shared across Watchmen windows and
          working directories. They stay active when Watchmen is closed.
          Unblocking a rule removes that restriction; other matching blocks
          still apply.
        </span>
      </div>
      {!admin && (
        <div className="banner">
          <Info size={17} />
          <span>
            Viewing saved rules. Administrator access is required to apply or
            unblock.
          </span>
          <button onClick={elevate}>Restart as administrator</button>
        </div>
      )}
      {state?.verificationError && (
        <div className="banner error">
          <Info size={17} />
          {state.verificationError}
        </div>
      )}
      {state?.error && (
        <div className="banner error" role="alert">
          {state.error}
        </div>
      )}
      <div className="rule-create-grid">
        <section className="card">
          <div className="card-heading">
            <div>
              <h2>
                <ShieldCheck size={19} /> Application access
              </h2>
              <p>Choose an executable or use Block in a traffic table.</p>
            </div>
          </div>
          <div className="rule-create-body">
            <button
              className="button"
              disabled={busy}
              onClick={() => pick(false)}
            >
              <FolderOpen size={16} />
              Choose an app to block
            </button>
            <button
              className="button primary"
              disabled={busy}
              onClick={() => pick(true)}
            >
              <ShieldCheck size={16} />
              Allow only one app
            </button>
            <p>
              Only-app mode restricts every other executable, including
              background services. It has its own review step and a Turn off
              control.
            </p>
          </div>
        </section>
        <section className="card">
          <div className="card-heading">
            <div>
              <h2>
                <Globe2 size={19} /> Countries and regions
              </h2>
              <p>Control IPv4 and IPv6 destinations across every app.</p>
            </div>
            <span className="count-pill">{selection.length} selected</span>
          </div>
          <div className="rule-create-body">
            <label className="policy-mode">
              Country rule mode
              <select
                aria-label="Country rule mode"
                value={countryMode}
                disabled={busy}
                onChange={(e) => setCountryMode(e.target.value)}
              >
                <option value="region">
                  Block selected countries / regions
                </option>
                <option value="onlyRegion">
                  Allow only selected countries / regions
                </option>
              </select>
            </label>
            <button
              className="button"
              disabled={busy}
              onClick={() => {
                setSelection(["CA", "US"]);
                setCountryMode("onlyRegion");
              }}
            >
              Allow Canada + US only
            </button>
            {countryMode === "onlyRegion" && (
              <div className="policy-options">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={allowLocalNetwork}
                    disabled={busy}
                    onChange={(e) => setAllowLocalNetwork(e.target.checked)}
                  />
                  Keep local-network traffic available
                </label>
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={allowUnknown}
                    disabled={busy}
                    onChange={(e) => setAllowUnknown(e.target.checked)}
                  />
                  Allow public addresses with unknown country
                </label>
                <p>
                  Everything outside your selection is blocked. Existing app and
                  destination blocks continue to apply.
                </p>
              </div>
            )}
            <div className="region-shortcuts">
              {catalog?.regions.map((region) => (
                <button
                  className={
                    "button " +
                    (region.countries.every((c) => selection.includes(c))
                      ? "selected"
                      : "")
                  }
                  key={region.name}
                  disabled={busy}
                  onClick={() =>
                    setSelection((current) =>
                      region.countries.every((c) => current.includes(c))
                        ? current.filter((c) => !region.countries.includes(c))
                        : [...new Set([...current, ...region.countries])],
                    )
                  }
                >
                  {region.name}
                </button>
              ))}
            </div>
            <div className="search">
              <Search size={15} />
              <input
                aria-label="Find countries"
                placeholder="Find a country or region…"
                value={countrySearch}
                onChange={(e) => setCountrySearch(e.target.value)}
              />
            </div>
            <div
              className="country-rule-picker"
              aria-label={
                countryMode === "onlyRegion"
                  ? "Countries to allow"
                  : "Countries to block"
              }
            >
              {countryRows.map((c) => (
                <label key={c.code}>
                  <input
                    type="checkbox"
                    checked={selection.includes(c.code)}
                    disabled={busy}
                    onChange={() =>
                      setSelection((current) =>
                        current.includes(c.code)
                          ? current.filter((code) => code !== c.code)
                          : [...current, c.code],
                      )
                    }
                  />
                  <span>{c.name}</span>
                  <small>{c.code}</small>
                </label>
              ))}
            </div>
            <div className="ai-controls">
              <button
                className="button danger"
                disabled={busy || !selection.length}
                onClick={() =>
                  preview({
                    kind: countryMode,
                    countries: selection,
                    allowLocalNetwork,
                    allowUnknown,
                  })
                }
              >
                <Ban size={15} />
                {countryMode === "onlyRegion"
                  ? "Review country-only mode"
                  : "Review region block"}
              </button>
              <button className="text-button" onClick={() => setSelection([])}>
                Clear selection
              </button>
            </div>
            <p>
              <a
                href="https://db-ip.com/db/lite.php"
                onClick={(e) => {
                  e.preventDefault();
                  window.watchmen?.openRuleDataSource();
                }}
              >
                IP Geolocation by DB-IP
              </a>{" "}
              · CC BY 4.0. Monthly, approximate country data is downloaded to
              prepare a review; traffic IPs are not sent to the dataset
              provider.
            </p>
          </div>
        </section>
      </div>
      <section className="card">
        <div className="card-heading">
          <div>
            <h2>
              Saved network rules{" "}
              <span className="count-pill">{state?.rules.length || 0}</span>
            </h2>
            <p>Active rules survive app exit and reboot.</p>
          </div>
          <div className="ai-controls">
            <button className="button" disabled={busy} onClick={refresh}>
              <RefreshCw size={15} />
              Refresh rules
            </button>
            <button
              className="button"
              disabled={busy || !admin}
              onClick={unblockAll}
            >
              <Unlock size={15} />
              Unblock all Watchmen rules
            </button>
          </div>
        </div>
        <div className="change-filters">
          <div className="search">
            <Search size={15} />
            <input
              aria-label="Search network rules"
              value={search}
              placeholder="Search apps, IPs or countries…"
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <select
            aria-label="Network rule status"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          >
            <option value="all">All saved</option>
            <option value="active">Active blocks</option>
            <option value="inactive">Unblocked</option>
          </select>
        </div>
        {busy && (
          <div className="banner" role="status">
            <LoaderCircle className="spin" size={16} />
            {state?.phase || "Updating Windows network rules…"}
          </div>
        )}
        <div className="table-scroll">
          <table aria-label="Saved network rules">
            <thead>
              <tr>
                <th>RULE / SCOPE</th>
                <th>STATUS</th>
                <th>DATA / CREATED</th>
                <th>ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr
                  key={rule.id}
                  {...rowAI("rule", rule.label, {
                    app:
                      rule.appPath?.split(/[\\/]/).pop() || "Any application",
                    ruleKind: rule.kind,
                    protocol: rule.protocol || "Any",
                    remotePort: rule.port || 0,
                    country: rule.countries.join(", ").slice(0, 1000),
                    enabled: rule.enabled,
                    partial: !!rule.partial,
                    rangeCount: rule.rangeCount || 0,
                    nativeRuleCount: rule.nativeRuleCount || 0,
                  })}
                >
                  <td>
                    <strong>{rule.label}</strong>
                    <small>
                      {
                        {
                          app: "Entire executable",
                          connection: "App + remote IP / protocol / port",
                          destination: "Remote IP · every app",
                          region: "Countries · every app",
                          onlyRegion: "Country-only mode / every app",
                          onlyApp: "Only-app mode · system wide",
                        }[rule.kind]
                      }
                    </small>
                    <code>
                      {rule.appPath ||
                        rule.address ||
                        (["region", "onlyRegion"].includes(rule.kind)
                          ? rule.countries.join(", ")
                          : "")}
                    </code>
                  </td>
                  <td>
                    <span
                      className={
                        "rule-state " + (rule.enabled ? "blocked" : "")
                      }
                    >
                      {!state?.isolationVerified
                        ? rule.enabled
                          ? "Saved active / unverified"
                          : "Saved inactive / unverified"
                        : rule.partial
                          ? "Partially applied"
                          : rule.enabled
                            ? rule.kind === "onlyApp"
                              ? "Isolation active"
                              : rule.kind === "onlyRegion"
                                ? "Country-only active"
                                : "Blocked"
                            : "Unblocked"}
                    </span>
                    {rule.kind === "onlyApp" && !state?.isolationVerified && (
                      <small>Saved state · unverified</small>
                    )}
                  </td>
                  <td>
                    {["region", "onlyRegion"].includes(rule.kind) ? (
                      <>
                        <strong>{rule.sourceMonth}</strong>
                        <small>
                          {rule.rangeCount.toLocaleString()} IP ranges · DB-IP
                        </small>
                      </>
                    ) : (
                      new Date(rule.createdAt).toLocaleDateString()
                    )}
                    <small>
                      {rule.nativeRuleCount} Windows filters / rules
                    </small>
                  </td>
                  <td>
                    <div className="ai-controls">
                      {rule.enabled ? (
                        <button
                          className="button"
                          disabled={busy || !admin}
                          onClick={() => toggle(rule)}
                        >
                          <Unlock size={14} />
                          {rule.kind === "onlyApp" ? "Turn off" : "Unblock"}
                        </button>
                      ) : rule.kind === "onlyApp" ? (
                        <button
                          className="button"
                          disabled={busy}
                          onClick={() => pick(true)}
                        >
                          Choose app again
                        </button>
                      ) : (
                        <button
                          className="button"
                          disabled={busy || !admin}
                          onClick={() => toggle(rule)}
                        >
                          <Ban size={14} />
                          Block again
                        </button>
                      )}
                      {!rule.enabled && (
                        <button
                          className="icon-button"
                          aria-label={`Remove saved rule ${rule.label}`}
                          disabled={busy || !admin}
                          onClick={() => forget(rule.id)}
                        >
                          <Trash2 size={15} />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!rules.length && (
            <div className="empty">
              <Shield size={27} />
              <h3>No matching network rules.</h3>
              <p>
                Use Block in a traffic table or choose an app or region above.
              </p>
            </div>
          )}
        </div>
        <div className="table-footer">
          Existing connections may take time to close after a policy change.
          Shared IPs can host several services; IP blocks affect every matching
          service in their scope.
        </div>
      </section>
    </div>
  );
}
import { rowAI } from "./row-overview";
