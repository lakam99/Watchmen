import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { CircleHelp, LoaderCircle, Shield, X } from "lucide-react";
import type { Insight, PreferencesStatus } from "./ai";
import "./row-overview.css";
export type RowInfo = {
  kind: string;
  label: string;
  facts: Record<string, string | number | boolean | null>;
};
export type AppResearch = {
  app: string | null;
  eligible: boolean;
  supported: boolean;
  status: string;
  text?: string;
  notice?: string;
  researchedAt?: string;
  cached?: boolean;
  cacheSavedAt?: string;
  provider?: string;
  model?: string;
  cacheNotice?: string;
  sources: { url: string; title: string }[];
};
export type RowInsight = Insight & {
  research: AppResearch;
  overviewNotice?: string;
};
export const rowAI = (
  kind: string,
  label: string,
  facts: RowInfo["facts"],
) => ({
  "data-ai-row": JSON.stringify({ kind, label, facts }),
  tabIndex: 0,
  "aria-haspopup": "menu" as const,
  "aria-keyshortcuts": "Shift+F10",
  title: "Right-click or press Shift+F10 for a short AI overview",
});
export function RowOverviewUI() {
  const [menu, setMenu] = useState<{
    row: RowInfo;
    x: number;
    y: number;
    origin: HTMLElement;
  } | null>(null);
  const [panel, setPanel] = useState<{
    id: string;
    row: RowInfo;
    busy: boolean;
    result?: RowInsight;
    preferences?: PreferencesStatus;
    error?: string;
  } | null>(null);
  const active = useRef<string | null>(null),
    menuElement = useRef<HTMLDivElement>(null),
    dialogElement = useRef<HTMLElement>(null),
    origin = useRef<HTMLElement | null>(null);
  function close() {
    if (active.current) void window.watchmen?.rowOverviewCancel(active.current);
    active.current = null;
    setPanel(null);
    origin.current?.focus({ preventScroll: true });
  }
  useEffect(() => {
    const show = (event: MouseEvent | KeyboardEvent) => {
      if (panel || !(event.target instanceof Element)) return;
      const row = event.target.closest<HTMLElement>("tbody tr[data-ai-row]");
      if (!row) return;
      try {
        const info = JSON.parse(row.dataset.aiRow || "");
        if (!info.kind || !info.facts) return;
        event.preventDefault();
        const bounds = row.getBoundingClientRect();
        const x = "clientX" in event ? event.clientX : bounds.left + 20;
        const y = "clientY" in event ? event.clientY : bounds.top + 15;
        setMenu({
          row: structuredClone(info),
          x: Math.max(8, Math.min(x, innerWidth - 246)),
          y: Math.max(8, Math.min(y, innerHeight - 86)),
          origin: row,
        });
      } catch {
        /* Preserve the native context menu for malformed/non-data rows. */
      }
    };
    const key = (event: KeyboardEvent) => {
      if (event.key === "Escape" && (menu || panel)) {
        event.preventDefault();
        event.stopImmediatePropagation();
        if (panel) close();
        else {
          menu?.origin.focus();
          setMenu(null);
        }
      } else if (
        event.key === "ContextMenu" ||
        (event.shiftKey && event.key === "F10")
      )
        show(event);
      else if (panel && event.key === "Tab") {
        const buttons = [
          ...(dialogElement.current?.querySelectorAll<HTMLButtonElement>(
            "button:not(:disabled)",
          ) || []),
        ];
        const first = buttons[0],
          last = buttons.at(-1);
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last?.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first?.focus();
        }
      }
    };
    const dismiss = (event: Event) => {
      if (!menuElement.current?.contains(event.target as Node)) setMenu(null);
    };
    const scroll = () => setMenu(null);
    document.addEventListener("contextmenu", show);
    document.addEventListener("keydown", key, true);
    document.addEventListener("pointerdown", dismiss);
    document.addEventListener("wheel", scroll, true);
    window.addEventListener("resize", scroll);
    return () => {
      document.removeEventListener("contextmenu", show);
      document.removeEventListener("keydown", key, true);
      document.removeEventListener("pointerdown", dismiss);
      document.removeEventListener("wheel", scroll, true);
      window.removeEventListener("resize", scroll);
    };
  }, [menu, panel]);
  useEffect(() => {
    menuElement.current
      ?.querySelector("button")
      ?.focus({ preventScroll: true });
  }, [menu]);
  useEffect(() => {
    if (panel?.id)
      dialogElement.current
        ?.querySelector("button")
        ?.focus({ preventScroll: true });
  }, [panel?.id]);
  useEffect(
    () => () => {
      if (active.current)
        void window.watchmen?.rowOverviewCancel(active.current);
    },
    [],
  );
  async function explain() {
    if (!menu) return;
    const row = menu.row,
      id = crypto.randomUUID();
    origin.current = menu.origin;
    active.current = id;
    setMenu(null);
    setPanel({ id, row, busy: true });
    try {
      if (!window.watchmen)
        throw new Error("Open Watchmen desktop to use AI overviews.");
      const preferences = await window.watchmen.preferences();
      if (active.current !== id) return;
      if (!preferences.ok) throw new Error(preferences.error);
      if (!preferences.value.hasToken) {
        setPanel({ id, row, busy: false, preferences: preferences.value });
        return;
      }
      setPanel({ id, row, busy: true, preferences: preferences.value });
      const result = await window.watchmen.rowOverview({ ...row, id });
      if (active.current !== id) return;
      setPanel({
        id,
        row,
        busy: false,
        preferences: preferences.value,
        ...(result.ok ? { result: result.value } : { error: result.error }),
      });
    } catch (error) {
      if (active.current === id)
        setPanel({
          id,
          row,
          busy: false,
          error:
            error instanceof Error
              ? error.message
              : "The row overview could not complete.",
        });
    }
  }
  async function researchApp(refresh = false) {
    if (!panel?.result || panel.busy || !window.watchmen) return;
    const previous = panel,
      id = crypto.randomUUID();
    active.current = id;
    setPanel({ ...previous, id, busy: true, error: undefined });
    try {
      const r = await window.watchmen.rowOverviewResearch({
        ...previous.row,
        id,
        refresh,
      });
      if (active.current !== id) return;
      setPanel({
        ...previous,
        id,
        busy: false,
        ...(r.ok
          ? { result: { ...previous.result!, research: r.value.research } }
          : { error: r.error }),
      });
    } catch {
      if (active.current === id)
        setPanel({
          ...previous,
          id,
          busy: false,
          error: "App research could not complete. Try again.",
        });
    }
  }
  async function openSource(url: string) {
    const id = active.current;
    try {
      const r = await window.watchmen?.rowOverviewSource(url);
      if (active.current === id && r && !r.ok)
        setPanel((p) => (p ? { ...p, error: r.error } : p));
    } catch {
      if (active.current === id)
        setPanel((p) =>
          p ? { ...p, error: "The cited source could not be opened." } : p,
        );
    }
  }
  return createPortal(
    <>
      {menu && (
        <div
          className="row-ai-menu"
          role="menu"
          aria-label="Row actions"
          ref={menuElement}
          style={{ left: menu.x, top: menu.y }}
        >
          <button role="menuitem" onClick={explain}>
            <CircleHelp size={16} />
            What is this?
          </button>
          <small>AI overview · shares row metadata</small>
        </div>
      )}
      {panel && (
        <div
          className="row-ai-backdrop"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) close();
          }}
        >
          <section
            className="row-ai-dialog card"
            role="dialog"
            aria-modal="true"
            aria-labelledby="row-ai-title"
            ref={dialogElement}
          >
            <header>
              <div>
                <CircleHelp size={18} />
                <h2 id="row-ai-title">What is this?</h2>
              </div>
              <button
                className="icon-button"
                aria-label="Close row overview"
                onClick={close}
              >
                <X size={18} />
              </button>
            </header>
            <strong className="row-ai-label">{panel.row.label}</strong>
            <span className="row-ai-kind">
              {panel.row.kind.replaceAll("_", " ")} · frozen row snapshot
            </span>
            <p className="row-ai-disclosure">
              <Shield size={15} />
              Read-only AI overview. Only bounded names, ports, status and
              counters are shared. Addresses, paths and packet contents are
              excluded. App research sends only the app name through your
              provider's web search when enabled or requested below.
            </p>
            {panel.busy && (
              <p className="row-ai-loading" role="status">
                <LoaderCircle size={16} className="spin" />
                {panel.result
                  ? "Researching app on web…"
                  : "Explaining this row and application…"}
              </p>
            )}
            {panel.error && (
              <p className="inline-error" role="alert">
                {panel.error}
              </p>
            )}
            {panel.preferences && !panel.preferences.hasToken && (
              <div>
                <p>Add an API token in Settings to use AI overviews.</p>
                <button
                  className="button primary"
                  onClick={() => {
                    close();
                    window.dispatchEvent(new Event("watchmen-ai-settings"));
                  }}
                >
                  Set up AI
                </button>
              </div>
            )}
            {panel.result && (
              <>
                <div className="row-ai-answer">{panel.result.text}</div>
                {panel.result.overviewNotice && (
                  <p className="inline-error" role="alert">
                    {panel.result.overviewNotice}
                  </p>
                )}
                <section
                  className="row-ai-research"
                  aria-label="Application research"
                >
                  <h3>
                    About the app
                    {panel.result.research.app
                      ? ` · ${panel.result.research.app}`
                      : ""}
                  </h3>
                  {panel.result.research.status === "completed" ? (
                    <>
                      <p className="row-ai-answer">
                        {panel.result.research.text}{" "}
                        {panel.result.research.sources.map((s, i) => (
                          <button
                            key={s.url}
                            className="row-ai-citation"
                            title={s.title}
                            aria-label={`Open source ${i + 1}: ${s.title}`}
                            onClick={() => openSource(s.url)}
                          >
                            [{i + 1}]
                          </button>
                        ))}
                      </p>
                      <small>
                        {panel.result.research.cached
                          ? "Cached research"
                          : "Web researched"}{" "}
                        ·{" "}
                        {panel.result.research.researchedAt
                          ? new Date(
                              panel.result.research.researchedAt,
                            ).toLocaleString()
                          : ""}
                      </small>
                      {panel.result.research.provider && (
                        <small>
                          {" "}
                          · {panel.result.research.provider} /{" "}
                          {panel.result.research.model}
                        </small>
                      )}
                      <ul>
                        {panel.result.research.sources.map((s) => (
                          <li key={s.url}>
                            <button
                              className="text-button"
                              onClick={() => openSource(s.url)}
                            >
                              {s.title}
                            </button>
                          </li>
                        ))}
                      </ul>
                      {panel.result.research.notice && (
                        <p className="inline-error" role="alert">
                          {panel.result.research.notice}
                        </p>
                      )}
                      {panel.result.research.cacheNotice && (
                        <p className="inline-error" role="status">
                          {panel.result.research.cacheNotice}
                        </p>
                      )}
                      <button
                        className="button"
                        disabled={
                          panel.busy || !panel.result.research.supported
                        }
                        onClick={() => researchApp(true)}
                      >
                        Refresh research
                      </button>
                      <p className="row-ai-disclosure">
                        Saved findings are reused until refreshed. Refresh runs
                        a new web search; provider charges may apply.
                      </p>
                    </>
                  ) : (
                    <p>
                      {panel.result.research.notice ||
                        (panel.result.research.eligible
                          ? panel.result.research.supported
                            ? "The overview above uses model knowledge. Web research has not been performed."
                            : "Use OpenAI or OpenRouter with its official endpoint for cited app research."
                          : "No specific searchable app name is available in this row. The overview uses the supplied metadata.")}
                    </p>
                  )}
                  {panel.result.research.eligible &&
                    panel.result.research.supported &&
                    panel.result.research.status !== "completed" && (
                      <>
                        <button
                          className="button"
                          disabled={panel.busy}
                          onClick={() => researchApp()}
                        >
                          Research app on web
                        </button>
                        <p className="row-ai-disclosure">
                          Searches only this app name once. Provider search
                          charges may apply. Your saved web permission is
                          unchanged.
                        </p>
                      </>
                    )}
                  <p className="row-ai-disclosure">
                    A name match does not verify the publisher, signature or
                    safety of this local executable.
                  </p>
                </section>
              </>
            )}
            <footer>
              {panel.result
                ? `${panel.result.provider} / ${panel.result.model}`
                : panel.preferences?.hasToken
                  ? `${panel.preferences.ai.provider} / ${panel.preferences.ai.model}`
                  : "Your configured AI provider"}
              <span>AI explanation · verify uncertain claims</span>
            </footer>
          </section>
        </div>
      )}
    </>,
    document.body,
  );
}
