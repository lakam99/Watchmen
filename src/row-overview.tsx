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
    result?: Insight;
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
              excluded.
            </p>
            {panel.busy && (
              <p className="row-ai-loading" role="status">
                <LoaderCircle size={16} className="spin" />
                Explaining this row…
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
              <div className="row-ai-answer">{panel.result.text}</div>
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
