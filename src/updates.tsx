import { useEffect, useRef, useState } from "react";
import { Download, RefreshCw, ExternalLink } from "lucide-react";
export type UpdateState = {
  currentVersion: string;
  availableVersion: string | null;
  phase: string;
  supported: boolean;
  autoCheck: boolean;
  autoDownload: boolean;
  percent: number;
  transferred: number;
  total: number;
  bytesPerSecond: number;
  checkedAt: string | null;
  error: string | null;
  message: string;
  repository: string;
  releaseUrl: string;
  installBlocked: string | null;
};
function useUpdates() {
  const [state, setState] = useState<UpdateState | null>(null),
    [error, setError] = useState(""),
    [saving, setSaving] = useState(false);
  const configuring = useRef(false);
  useEffect(() => {
    let active = true;
    const poll = async () => {
      const r = await window.watchmen?.updatesStatus();
      if (active && !configuring.current && r?.ok) setState(r.value);
    };
    poll();
    const timer = setInterval(poll, 1000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);
  const run = async (action: () => Promise<any> | undefined) => {
    setError("");
    const r = await action();
    if (r?.ok) setState(r.value);
    else if (r) setError(r.error);
  };
  const configure = async (input: {
    autoCheck: boolean;
    autoDownload: boolean;
  }) => {
    if (configuring.current) return;
    const previous = state;
    configuring.current = true;
    setSaving(true);
    setState((value) => (value ? { ...value, ...input } : value));
    setError("");
    try {
      const result = await window.watchmen?.updatesConfigure(input);
      if (result?.ok) setState(result.value);
      else {
        setState(previous);
        if (result) setError(result.error);
      }
    } finally {
      configuring.current = false;
      setSaving(false);
    }
  };
  return { state, error, run, configure, saving };
}
function InstallButton({
  state,
  run,
}: {
  state: UpdateState;
  run: (action: () => Promise<any> | undefined) => void;
}) {
  return (
    <button
      className="button primary"
      disabled={!!state.installBlocked || state.phase !== "ready"}
      title={
        state.installBlocked ||
        "Install the verified release and restart this window"
      }
      onClick={() => run(() => window.watchmen?.updatesInstall())}
    >
      Install &amp; restart
    </button>
  );
}
export function UpdateBanner() {
  const { state, error, run } = useUpdates();
  if (state?.phase !== "ready" && state?.phase !== "installing") return null;
  return (
    <div className="banner update-banner">
      <Download size={18} />
      <span>
        <strong>Watchmen {state.availableVersion} is ready.</strong>{" "}
        {state.installBlocked || "Restart this window when you are ready."}
        {error && <small role="alert">{error}</small>}
      </span>
      <InstallButton state={state} run={run} />
    </div>
  );
}
export function UpdateSettings() {
  const { state, error, run, configure, saving } = useUpdates();
  if (!state) return null;
  const busy = ["checking", "downloading", "installing"].includes(state.phase);
  return (
    <section className="updates-setting" aria-label="App updates">
      <h3>
        <RefreshCw size={17} /> App updates{" "}
        <small>v{state.currentVersion}</small>
      </h3>
      <p>
        Stable Windows releases from {state.repository}. Downloads are verified
        before installation. Your traffic profile, credentials and persistent
        network rules stay in place.
      </p>
      <label className="checkbox-label">
        <input
          type="checkbox"
          checked={state.autoCheck}
          disabled={!state.supported || saving}
          onChange={(e) =>
            configure({
              autoCheck: e.target.checked,
              autoDownload: state.autoDownload,
            })
          }
        />
        Check automatically on launch and every six hours
      </label>
      <label className="checkbox-label">
        <input
          type="checkbox"
          checked={state.autoDownload}
          disabled={!state.supported || saving}
          onChange={(e) =>
            configure({
              autoCheck: state.autoCheck,
              autoDownload: e.target.checked,
            })
          }
        />
        Download available updates in the background
      </label>
      <p role="status">
        {state.message}
        {state.availableVersion && ` (v${state.availableVersion})`}
      </p>
      {state.phase === "downloading" && (
        <div>
          <progress
            aria-label="Update download progress"
            value={state.percent}
            max={100}
          />
          <small>
            {Math.round(state.percent)}% -{" "}
            {(state.transferred / 1048576).toFixed(1)} /{" "}
            {(state.total / 1048576).toFixed(1)} MB
          </small>
        </div>
      )}
      {(error || state.error) && (
        <p className="inline-error" role="alert">
          {error || state.error}
        </p>
      )}
      {state.installBlocked && state.phase === "ready" && (
        <p>{state.installBlocked}</p>
      )}
      <div className="ai-controls">
        <button
          className="button"
          disabled={busy || !state.supported || state.phase === "ready"}
          onClick={() => run(() => window.watchmen?.updatesCheck())}
        >
          <RefreshCw size={15} />
          Check for updates
        </button>
        {state.phase === "available" && (
          <button
            className="button primary"
            onClick={() => run(() => window.watchmen?.updatesDownload())}
          >
            <Download size={15} />
            Download update
          </button>
        )}
        {state.phase === "ready" && <InstallButton state={state} run={run} />}
        <button
          className="text-button"
          onClick={() => window.watchmen?.updatesRelease()}
        >
          <ExternalLink size={14} />
          Release notes
        </button>
      </div>
      {state.checkedAt && (
        <small>Last checked {new Date(state.checkedAt).toLocaleString()}</small>
      )}
      <p className="update-restart-note">
        Installation restarts this window. Active rule changes and packet
        captures must finish first. Quit other Watchmen instances from their
        tray icons before installing. Closing a window keeps monitoring active.
      </p>
    </section>
  );
}
