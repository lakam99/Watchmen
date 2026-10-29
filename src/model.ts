export type Location = {
  country: string;
  code: string;
  city: string;
  org: string;
  latitude?: number;
  longitude?: number;
};
export type Flow = {
  id: string;
  pid: number;
  app: string;
  processPath: string;
  protocol: string;
  localAddress: string;
  localPort: number;
  remoteAddress: string;
  remotePort: number;
  state: string;
  active: boolean;
  received: number;
  sent: number;
  rxRate: number;
  txRate: number;
  firstSeen: string;
  lastSeen: string;
};
export type Snapshot = {
  timestamp: string;
  startedAt: string;
  admin: boolean;
  tracing: boolean;
  traceError: string | null;
  errors: string[];
  eventsLost: number;
  evictedFlows: number;
  rxRate: number;
  txRate: number;
  adapters: {
    id: string;
    name: string;
    description: string;
    rxRate: number;
    txRate: number;
    received: number;
    sent: number;
  }[];
  flows: Flow[];
  locationsEnabled: boolean;
  locationStatus: string;
  locations: Record<string, Location>;
  agentError: string | null;
  alertCount?: number;
  profileStatus?: {
    available: boolean;
    databasePath: string;
    recording: boolean;
    error: string | null;
  };
};
export type GroupBy = "app" | "destination" | "country" | "protocol";
export type Group = {
  id: string;
  name: string;
  subtitle: string;
  flows: Flow[];
  received: number;
  sent: number;
  rxRate: number;
  txRate: number;
  active: number;
};
export function scope(ip: string): "local" | "internet" | "listener" {
  if (ip === "*" || ip === "0.0.0.0" || ip === "::") return "listener";
  if (ip.includes(":")) {
    const a = ip.toLowerCase();
    if (a.startsWith("::ffff:")) return scope(a.slice(7));
    return a === "::1" ||
      /^f[cd]/.test(a) ||
      /^fe[89ab]/.test(a) ||
      a.startsWith("ff")
      ? "local"
      : "internet";
  }
  const [a, b] = ip.split(".").map(Number);
  return a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127)
    ? "local"
    : "internet";
}
export function groupFlows(
  flows: Flow[],
  by: GroupBy,
  locations: Record<string, Location>,
): Group[] {
  const groups = new Map<string, Group>();
  for (const f of flows) {
    const place = locations[f.remoteAddress];
    const country =
      scope(f.remoteAddress) === "local"
        ? "Local network"
        : scope(f.remoteAddress) === "listener"
          ? "Listening endpoints"
          : place?.country || "Unresolved";
    const id =
      by === "app"
        ? f.app + "|" + f.processPath
        : by === "destination"
          ? f.remoteAddress
          : by === "country"
            ? country
            : f.protocol;
    let g = groups.get(id);
    if (!g) {
      g = {
        id,
        name:
          by === "app"
            ? f.app
            : by === "destination"
              ? f.remoteAddress
              : by === "country"
                ? country
                : f.protocol,
        subtitle:
          by === "app"
            ? ""
            : by === "destination"
              ? place
                ? [place.city, place.country].filter(Boolean).join(", ")
                : scope(f.remoteAddress) === "internet"
                  ? "Public destination"
                  : scope(f.remoteAddress) === "listener"
                    ? "Local listening socket"
                    : "Local network"
              : by === "country"
                ? "IP location · approximate"
                : "Transport protocol",
        flows: [],
        received: 0,
        sent: 0,
        rxRate: 0,
        txRate: 0,
        active: 0,
      };
      groups.set(id, g);
    }
    g.flows.push(f);
    g.received += f.received;
    g.sent += f.sent;
    g.rxRate += f.rxRate;
    g.txRate += f.txRate;
    if (f.active) g.active++;
  }
  return [...groups.values()].map((g) => ({
    ...g,
    subtitle:
      by === "app"
        ? `${new Set(g.flows.map((f) => f.pid)).size} process${new Set(g.flows.map((f) => f.pid)).size === 1 ? "" : "es"} · ${new Set(g.flows.map((f) => f.remoteAddress).filter((a) => scope(a) !== "listener")).size} destinations`
        : g.subtitle,
  }));
}
export function bytes(value: number, rate = false) {
  if (!Number.isFinite(value) || value < 0) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (value >= 1024 && i < 4) {
    value /= 1024;
    i++;
  }
  return `${value.toFixed(i === 0 ? 0 : value < 10 ? 1 : 0)} ${units[i]}${rate ? "/s" : ""}`;
}
