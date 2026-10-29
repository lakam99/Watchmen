using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

if(args.Length>0 && (args[0]=="--firewall" || args[0]=="--unblock-watchmen")) { await Firewall.Run(args[0]=="--unblock-watchmen"); return; }
if(args.Length==3 && args[0] is "--connect-probe" or "--udp-probe" && int.TryParse(args[2],out var probePort) && probePort is >0 and <=65535){await FirewallProbe.Connect(args[1],probePort,args[0]=="--udp-probe");return;}
if(args.Length==3 && args[0]=="--test-app-isolation"){await FirewallProbe.Isolation(args[1],args[2]);return;}

if(args.Length>0&&args[0]=="--raw-packets"){
    await RawPackets.Run(args.Length>1&&int.TryParse(args[1],out var duration)?duration:10);
    return;
}

var gate = new object();
var flows = new Dictionary<string, Flow>();
var started = DateTimeOffset.UtcNow;
var cts = new CancellationTokenSource();
TraceEventSession? trace = null;
string? traceError = null;
bool tracing = false;
int evicted = 0;
var admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
_ = Task.Run(async () => { while (await Console.In.ReadLineAsync() != null) { } cts.Cancel(); });

void Observe(int pid, string src, int sport, string dst, int dport, int size, string protocol, bool incoming)
{
    if (size < 0 || pid < 0) return;
    // TCP events retain the owning socket in saddr/sport, including on receive.
    // UDP receive events use packet direction, so their destination is local.
    // The asymmetric loopback test verifies both conventions for IPv4 and IPv6.
    bool reverse = incoming && protocol == "UDP";
    var local = reverse ? dst : src; var remote = reverse ? src : dst;
    var lp = reverse ? dport : sport; var rp = reverse ? sport : dport;
    lock (gate)
    {
        var key = Flow.Key(pid, protocol, local, lp, remote, rp);
        if (!flows.TryGetValue(key, out var flow)) { flow = new Flow(pid, protocol, local, lp, remote, rp); flows[key] = flow; }
        if (incoming) flow.Received += size; else flow.Sent += size;
        flow.LastSeen = DateTimeOffset.UtcNow;
    }
}
if (admin)
{
    try
    {
        trace = new TraceEventSession("Watchmen-" + Environment.ProcessId) { StopOnDispose = true };
        trace.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);
        trace.Source.Kernel.TcpIpSend += d => Observe(d.ProcessID, d.saddr.ToString(), d.sport, d.daddr.ToString(), d.dport, d.size, "TCP", false);
        trace.Source.Kernel.TcpIpRecv += d => Observe(d.ProcessID, d.saddr.ToString(), d.sport, d.daddr.ToString(), d.dport, d.size, "TCP", true);
        trace.Source.Kernel.TcpIpSendIPV6 += d => Observe(d.ProcessID, d.saddr.ToString(), d.sport, d.daddr.ToString(), d.dport, d.size, "TCP", false);
        trace.Source.Kernel.TcpIpRecvIPV6 += d => Observe(d.ProcessID, d.saddr.ToString(), d.sport, d.daddr.ToString(), d.dport, d.size, "TCP", true);
        trace.Source.Kernel.UdpIpSend += d => Observe(d.ProcessID, d.saddr.ToString(), d.sport, d.daddr.ToString(), d.dport, d.size, "UDP", false);
        trace.Source.Kernel.UdpIpRecv += d => Observe(d.ProcessID, d.saddr.ToString(), d.sport, d.daddr.ToString(), d.dport, d.size, "UDP", true);
        trace.Source.Kernel.UdpIpSendIPV6 += d => Observe(d.ProcessID, d.saddr.ToString(), d.sport, d.daddr.ToString(), d.dport, d.size, "UDP", false);
        trace.Source.Kernel.UdpIpRecvIPV6 += d => Observe(d.ProcessID, d.saddr.ToString(), d.sport, d.daddr.ToString(), d.dport, d.size, "UDP", true);
        tracing = true;
        _ = Task.Run(() => { try { trace.Source.Process(); } catch (Exception e) { traceError = e.Message; tracing = false; } });
    }
    catch (Exception e) { traceError = e.Message; trace?.Dispose(); trace = null; }
}
var previousAdapters = new Dictionary<string, (long rx, long tx)>();
var watch = Stopwatch.StartNew(); double previousTime = watch.Elapsed.TotalSeconds;
try
{
    while (!cts.IsCancellationRequested)
    {
        var now = DateTimeOffset.UtcNow;
        double seconds = Math.Max(.1, watch.Elapsed.TotalSeconds - previousTime); previousTime = watch.Elapsed.TotalSeconds;
        List<SocketRow> sockets = []; List<string> errors = [];
        foreach (int family in new[] { 2, 23 }) foreach (bool udp in new[] { false, true })
            {
                try { sockets.AddRange(Native.Read(family, udp)); } catch (Exception e) { errors.Add(e.Message); }
            }
        object[] output;
        lock (gate)
        {
            foreach (var f in flows.Values) { f.Active = false; f.Present = false; }
            foreach (var s in sockets)
            {
                var key = Flow.Key(s.Pid, s.Protocol, s.LocalAddress, s.LocalPort, s.RemoteAddress, s.RemotePort);
                if (!flows.TryGetValue(key, out var f)) { f = new Flow(s.Pid, s.Protocol, s.LocalAddress, s.LocalPort, s.RemoteAddress, s.RemotePort); flows[key] = f; }
                f.Present = true; f.Active = s.Protocol == "UDP" || s.State is not ("TimeWait" or "Closed" or "DeleteTcb"); f.State = s.State; f.LastSeen = now;
            }
            // Bound memory for long-running captures. Export discloses the eviction count.
            if (flows.Count > 10000) { foreach (var f in flows.Values.Where(f => !f.Active).OrderBy(f => f.LastSeen).Take(flows.Count - 10000).ToArray()) { flows.Remove(f.Id); evicted++; } }
            output = flows.Values.Select(f =>
            {
                var rx = Math.Max(0, f.Received - f.PreviousReceived) / seconds; var tx = Math.Max(0, f.Sent - f.PreviousSent) / seconds;
                f.PreviousReceived = f.Received; f.PreviousSent = f.Sent;
                return (object)new { id = f.Id, pid = f.Pid, app = f.App, processPath = f.ProcessPath, protocol = f.Protocol, localAddress = f.LocalAddress, localPort = f.LocalPort, remoteAddress = f.RemoteAddress, remotePort = f.RemotePort, state = f.Present ? f.State : "Closed", active = f.Active || rx + tx > 0, received = f.Received, sent = f.Sent, rxRate = rx, txRate = tx, firstSeen = f.FirstSeen, lastSeen = f.LastSeen };
            }).ToArray();
        }
        var adapters = new List<object>(); double totalRx = 0, totalTx = 0;
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
        {
            try { var stats = nic.GetIPStatistics(); double rx = 0, tx = 0; if (previousAdapters.TryGetValue(nic.Id, out var old)) { rx = Math.Max(0, stats.BytesReceived - old.rx) / seconds; tx = Math.Max(0, stats.BytesSent - old.tx) / seconds; } previousAdapters[nic.Id] = (stats.BytesReceived, stats.BytesSent); totalRx += rx; totalTx += tx; adapters.Add(new { id = nic.Id, name = nic.Name, description = nic.Description, rxRate = rx, txRate = tx, received = stats.BytesReceived, sent = stats.BytesSent }); } catch { }
        }
        int eventsLost = 0; try { if (tracing && trace != null) eventsLost = trace.EventsLost; } catch { }
        Console.WriteLine(JsonSerializer.Serialize(new { timestamp = now, startedAt = started, admin, tracing, traceError, errors, eventsLost, evictedFlows = evicted, rxRate = totalRx, txRate = totalTx, adapters, flows = output }));
        try { await Task.Delay(1000, cts.Token); } catch (OperationCanceledException) { }
    }
}
finally { trace?.Dispose(); }

sealed class Flow
{
    public static string Key(int p, string protocol, string local, int lp, string remote, int rp) => $"{p}|{protocol}|{local}|{lp}|{remote}|{rp}";
    public string Id, App, ProcessPath = "", Protocol, LocalAddress, RemoteAddress, State = "Observed";
    public int Pid, LocalPort, RemotePort; public long Received, Sent, PreviousReceived, PreviousSent;
    public bool Active, Present; public DateTimeOffset FirstSeen = DateTimeOffset.UtcNow, LastSeen = DateTimeOffset.UtcNow;
    public Flow(int pid, string protocol, string local, int lp, string remote, int rp)
    {
        Pid = pid; Protocol = protocol; LocalAddress = local; LocalPort = lp; RemoteAddress = remote; RemotePort = rp; Id = Key(pid, protocol, local, lp, remote, rp); App = pid == 0 ? "System (unattributed)" : pid == 4 ? "System" : "Process " + pid;
        if (pid > 4) try { using var p = Process.GetProcessById(pid); App = p.ProcessName; try { ProcessPath = p.MainModule?.FileName ?? ""; } catch { } } catch { }
    }
}
record SocketRow(int Pid, string Protocol, string LocalAddress, int LocalPort, string RemoteAddress, int RemotePort, string State);
static class Native
{
    [DllImport("iphlpapi.dll")] static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int family, int tableClass, uint reserved);
    [DllImport("iphlpapi.dll")] static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool order, int family, int tableClass, uint reserved);
    public static List<SocketRow> Read(int family, bool udp)
    {
        int size = 0; uint Query(IntPtr p) => udp ? GetExtendedUdpTable(p, ref size, false, family, 1, 0) : GetExtendedTcpTable(p, ref size, false, family, 5, 0);
        Query(IntPtr.Zero); if (size < 4) return []; IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            var status = Query(ptr); if (status == 122) { Marshal.FreeHGlobal(ptr); ptr = Marshal.AllocHGlobal(size); status = Query(ptr); }
            if (status != 0) throw new Exception($"{(udp ? "UDP" : "TCP")} IPv{(family == 2 ? 4 : 6)} table: Windows error {status}");
            int count = Marshal.ReadInt32(ptr); int rowSize = family == 2 ? (udp ? 12 : 24) : (udp ? 28 : 56); List<SocketRow> rows = [];
            for (int i = 0; i < count; i++)
            {
                var p = IntPtr.Add(ptr, 4 + i * rowSize); int U(int offset) => Marshal.ReadInt32(p, offset); int Port(int offset) => (ushort)IPAddress.NetworkToHostOrder((short)U(offset));
                string Addr(int offset, bool v6, int scope = 0) { byte[] bytes = new byte[v6 ? 16 : 4]; Marshal.Copy(IntPtr.Add(p, offset), bytes, 0, bytes.Length); return v6 ? new IPAddress(bytes, (uint)scope).ToString() : new IPAddress(bytes).ToString(); }
                if (family == 2) rows.Add(udp ? new(U(8), "UDP", Addr(0, false), Port(4), "*", 0, "Listening") : new(U(20), "TCP", Addr(4, false), Port(8), Addr(12, false), Port(16), ((TcpState)U(0)).ToString()));
                else rows.Add(udp ? new(U(24), "UDP", Addr(0, true, U(16)), Port(20), "*", 0, "Listening") : new(U(52), "TCP", Addr(0, true, U(16)), Port(20), Addr(24, true, U(40)), Port(44), ((TcpState)U(48)).ToString()));
            }
            return rows;
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }
}
