using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text.Json;

static class RawPackets
{
    public static async Task Run(int seconds)
    {
        if (seconds < 5 || seconds > 30) { Console.WriteLine(JsonSerializer.Serialize(new { type = "error", message = "Choose a 5–30 second capture." })); return; }
        if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) { Console.WriteLine(JsonSerializer.Serialize(new { type = "error", message = "Administrator access is required for live packet capture." })); return; }
        using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));
        _ = Task.Run(async () => { try { while (await Console.In.ReadLineAsync() != null) { } cancel.Cancel(); } catch { } });
        var sockets = new List<Socket>();
        var outputLock = new object();
        long count = 0;
        void Emit(object value) { lock (outputLock) Console.WriteLine(JsonSerializer.Serialize(value)); }
        foreach (var address in NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .SelectMany(n => n.GetIPProperties().UnicastAddresses).Select(a => a.Address).Where(a => a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a)).Distinct().Take(16))
        {
            Socket? socket = null;
            try
            {
                socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                socket.ReceiveBufferSize = 4 * 1024 * 1024;
                socket.Bind(new IPEndPoint(address, 0));
                // RCVALL_IPLEVEL captures IP traffic received by this interface;
                // it does not enable promiscuous mode on the network adapter.
                socket.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(3), null);
                sockets.Add(socket);
            }
            catch { socket?.Dispose(); }
        }
        if (sockets.Count == 0) { Emit(new { type = "error", message = "No active IPv4 interface supports Windows IP capture." }); return; }
        Emit(new { type = "ready", interfaces = sockets.Count });
        var tasks = sockets.Select(async socket =>
        {
            var buffer = new byte[65535];
            try
            {
                while (!cancel.IsCancellationRequested)
                {
                    var size = await socket.ReceiveAsync(buffer.AsMemory(), SocketFlags.None, cancel.Token);
                    if (size == 0) continue;
                    var number = Interlocked.Increment(ref count);
                    if (number <= 500) Emit(new { type = "packet", timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), length = size, data = Convert.ToBase64String(buffer, 0, Math.Min(size, 512)) });
                    if (number >= 100000) cancel.Cancel();
                }
            }
            catch (OperationCanceledException) { }
            catch (SocketException) { }
            catch (ObjectDisposedException) { }
        }).ToArray();
        try { await Task.WhenAll(tasks); }
        finally
        {
            foreach (var socket in sockets) { try { socket.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(0), null); } catch { } socket.Dispose(); }
        }
        Emit(new { type = "done", totalRecords = count, interfaces = sockets.Count });
    }
}
