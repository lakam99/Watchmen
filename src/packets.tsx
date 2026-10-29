import { useState, useEffect } from "react";
import {
  Radio,
  FolderOpen,
  Square,
  Play,
  Search,
  ChevronRight,
  Info,
  Shield,
  LoaderCircle,
} from "lucide-react";
export type Packet = {
  id: string;
  timestamp: number;
  protocol: string;
  source: string;
  destination: string;
  sourcePort: number | null;
  destinationPort: number | null;
  direction: string;
  app: string;
  summary: string;
  length: number;
  capturedLength: number;
  truncated: boolean;
  encrypted: boolean;
  headers?: { name: string; value: string }[];
  payloadText?: string;
  hexHeaders?: string;
};
export type PacketState = {
  active: boolean;
  processing: boolean;
  error: string | null;
  source: string;
  startedAt: number | null;
  endsAt: number | null;
  packets: Packet[];
  totalRecords: number;
  displayLimit: number;
  limited: boolean;
};
const endpoint = (ip: string, port: number | null) =>
  ip
    ? (ip.includes(":") ? `[${ip}]` : ip) + (port !== null ? ":" + port : "")
    : "—";
export function PacketInspector({
  admin,
  elevate,
  initialSearch = "",
}: {
  admin: boolean;
  elevate: () => void;
  initialSearch?: string;
}) {
  const [data, setData] = useState<PacketState | null>(null),
    [search, setSearch] = useState(initialSearch),
    [direction, setDirection] = useState("all"),
    [seconds, setSeconds] = useState(10),
    [selected, setSelected] = useState<Packet | null>(null),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [now, setNow] = useState(Date.now());
  useEffect(() => {
    let active = true;
    const refresh = async () => {
      const r = await window.watchmen?.packetsStatus();
      if (active && r) {
        if (r.ok) setData(r.value);
        else setError(r.error);
      }
      if (active) setNow(Date.now());
    };
    refresh();
    const timer = setInterval(refresh, 1000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);
  const act = async (action: "start" | "stop" | "import") => {
    setBusy(true);
    setError("");
    try {
      const r = await (action === "start"
        ? window.watchmen?.packetsStart(seconds)
        : action === "stop"
          ? window.watchmen?.packetsStop()
          : window.watchmen?.packetsImport());
      if (r) {
        if (r.ok) {
          if (r.value) {
            setData(r.value);
            setSelected(null);
          }
        } else setError(r.error);
      }
    } finally {
      setBusy(false);
    }
  };
  const rows = (data?.packets || []).filter(
    (p) =>
      (direction === "all" || p.direction === direction) &&
      [
        p.source,
        p.destination,
        p.app,
        p.protocol,
        p.summary,
        p.sourcePort,
        p.destinationPort,
      ]
        .join(" ")
        .toLowerCase()
        .includes(search.toLowerCase()),
  );
  return (
    <div className="packets-view" aria-label="Packet inspector">
      <div className="banner">
        <Shield size={17} />
        <span>
          On-demand local capture. Readable HTTP/text and DNS are decoded;
          TLS/HTTPS/QUIC stay encrypted. Sensitive text headers are redacted.
          Packet contents never enter AI requests.
        </span>
      </div>
      <section className="card packet-controls">
        <div>
          <h2>
            <Radio size={18} />A closer look at sent and received packets
          </h2>
          <p>
            Live Windows IPv4 capture · first 512 bytes per record · up to 500
            displayed. Import PCAP files for IPv4 and IPv6.
          </p>
        </div>
        <div className="ai-controls">
          <select
            aria-label="Packet capture duration"
            value={seconds}
            disabled={data?.active || busy}
            onChange={(e) => setSeconds(Number(e.target.value))}
          >
            {[5, 10, 20, 30].map((s) => (
              <option key={s} value={s}>
                {s} seconds
              </option>
            ))}
          </select>
          {data?.active ? (
            <button
              className="button primary"
              disabled={busy || data.processing}
              onClick={() => act("stop")}
            >
              <Square size={14} />
              Stop capture
            </button>
          ) : (
            <button
              className="button primary"
              disabled={busy || data?.processing || !admin}
              onClick={() => act("start")}
            >
              <Play size={14} />
              Capture packets
            </button>
          )}
          <button
            className="button"
            disabled={busy || data?.active || data?.processing}
            onClick={() => act("import")}
          >
            <FolderOpen size={14} />
            Open PCAP
          </button>
          {!admin && (
            <button className="button" onClick={elevate}>
              <Shield size={14} />
              Restart as administrator
            </button>
          )}
        </div>
        {(data?.active || data?.processing) && (
          <div className="capture-progress" role="status">
            <LoaderCircle size={15} className="spin" />
            {data.active
              ? `Capturing · ${Math.max(0, Math.ceil(((data.endsAt || now) - now) / 1000))}s remaining`
              : "Decoding capture…"}
          </div>
        )}
        <small>
          Live packets stay in memory; imported files are left intact. Capture
          covers active IPv4 interfaces and can show duplicates across adapters.
          No stream reassembly or TLS decryption is performed.
        </small>
      </section>
      {(error || data?.error) && (
        <div className="banner error" role="alert">
          {error || data?.error}
        </div>
      )}
      <section className="card">
        <div className="card-heading">
          <div>
            <h2>
              Captured records{" "}
              <span className="count-pill">{data?.totalRecords || 0}</span>
            </h2>
            <p>
              {data?.source ||
                "Start a short capture or open a local PCAP/PCAPNG file."}
            </p>
          </div>
          <select
            aria-label="Packet direction"
            value={direction}
            onChange={(e) => setDirection(e.target.value)}
          >
            <option value="all">All directions</option>
            {["Outgoing", "Incoming", "Local", "Unknown"].map((v) => (
              <option key={v}>{v}</option>
            ))}
          </select>
        </div>
        <div className="profile-search search">
          <Search size={16} />
          <input
            aria-label="Search packets"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search addresses, apps, protocols, or readable summaries…"
          />
        </div>
        <div className="packet-table-scroll">
          <table aria-label="Captured packets">
            <thead>
              <tr>
                <th>TIME / DIRECTION</th>
                <th>APP / PROTOCOL</th>
                <th>SOURCE → DESTINATION</th>
                <th>SUMMARY</th>
                <th>BYTES</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((p) => (
                <tr
                  key={p.id}
                  tabIndex={0}
                  aria-label={`Read packet ${p.id}`}
                  className={selected?.id === p.id ? "selected-row" : ""}
                  onClick={async () => {
                    const r = await window.watchmen?.packetDetail(p.id);
                    if (r) {
                      if (r.ok) setSelected(r.value);
                      else setError(r.error);
                    }
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") e.currentTarget.click();
                  }}
                >
                  <td>
                    {new Date(p.timestamp).toLocaleTimeString()}
                    <small>{p.direction}</small>
                  </td>
                  <td>
                    <strong>{p.app}</strong>
                    <small>{p.protocol}</small>
                  </td>
                  <td className="packet-endpoint">
                    {endpoint(p.source, p.sourcePort)}
                    <small>
                      → {endpoint(p.destination, p.destinationPort)}
                    </small>
                  </td>
                  <td>{p.summary}</td>
                  <td>
                    {p.capturedLength}
                    {p.truncated ? " / " + p.length : ""}
                  </td>
                  <td>
                    <ChevronRight size={14} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!rows.length && (
            <div className="empty">
              <Radio size={24} />
              <h3>
                {data?.active ? "Capture in progress." : "No matching packets."}
              </h3>
              <p>
                {data?.active
                  ? "The readable snapshot appears when capture stops."
                  : "Try another filter, capture packets, or import a supported file."}
              </p>
            </div>
          )}
        </div>
        <div className="table-footer">
          <span>
            {rows.length} displayed matches ·{" "}
            {data?.limited ? "first 500 records retained" : "up to 500 records"}{" "}
            · attribution is a current socket-tuple match, when unique.
          </span>
        </div>
      </section>
      {selected && (
        <section className="card packet-detail" aria-label="Packet contents">
          <div className="card-heading">
            <div>
              <h2>
                Packet {selected.id} · {selected.protocol}
              </h2>
              <p>
                {endpoint(selected.source, selected.sourcePort)} →{" "}
                {endpoint(selected.destination, selected.destinationPort)}
              </p>
            </div>
            <span className="badge">
              {selected.encrypted
                ? "Encrypted / secure protocol"
                : selected.truncated
                  ? "Truncated capture"
                  : "Decoded record"}
            </span>
          </div>
          <div className="packet-detail-body">
            <dl>
              {selected.headers?.map((h, i) => (
                <div key={i}>
                  <dt>{h.name}</dt>
                  <dd>{h.value}</dd>
                </div>
              ))}
            </dl>
            <h3>Readable payload</h3>
            <pre>
              {selected.payloadText ||
                "No application payload in this record (for example, a TCP acknowledgment or handshake)."}
            </pre>
            <h3>Header bytes</h3>
            <pre className="packet-hex">
              {selected.hexHeaders || "Header bytes unavailable."}
            </pre>
            <p>
              <Info size={13} />
              Text previews redact common credential headers and token fields.
              Binary and encrypted application data are not presented as
              plaintext.
            </p>
          </div>
        </section>
      )}
    </div>
  );
}
