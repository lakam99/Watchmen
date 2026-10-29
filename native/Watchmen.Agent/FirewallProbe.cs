using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;

static class FirewallProbe
{
    public static async Task Connect(string host, int port, bool udp = false)
    {
        try { using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(udp ? 1500 : 3000)); if (udp) { using var socket = new UdpClient(IPAddress.Parse(host).AddressFamily); socket.Connect(host, port); await socket.SendAsync(new byte[] { 0x57 }, cancel.Token); var reply = await socket.ReceiveAsync(cancel.Token); if (reply.Buffer.Length != 1 || reply.Buffer[0] != 0x57) throw new InvalidOperationException(); } else { using var socket = new TcpClient(); await socket.ConnectAsync(host, port, cancel.Token); } Console.WriteLine("{\"connected\":true}"); }
        catch (Exception e) { Console.WriteLine(JsonSerializer.Serialize(new { connected = false, error = e is SocketException socket ? socket.SocketErrorCode.ToString() : "Timed out" })); }
    }
    static async Task<bool> Probe(string executable, string address, int port, bool udp = false)
    {
        var info = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string value in new[] { udp ? "--udp-probe" : "--connect-probe", address, port.ToString() }) info.ArgumentList.Add(value);
        using var process = Process.Start(info) ?? throw new InvalidOperationException("The test probe could not start.");
        var text = process.StandardOutput.ReadToEndAsync();
        await process.WaitForExitAsync();
        return JsonDocument.Parse(await text).RootElement.GetProperty("connected").GetBoolean();
    }
    public static async Task Isolation(string selected, string other)
    {
        using var cancel = new CancellationTokenSource();
        var v4 = new TcpListener(IPAddress.Loopback, 0); v4.Start(); int port = ((IPEndPoint)v4.LocalEndpoint).Port;
        var v6 = new TcpListener(IPAddress.IPv6Loopback, port); v6.Server.DualMode = false; v6.Start();
        using var udp4 = new UdpClient(new IPEndPoint(IPAddress.Loopback, port));
        using var udp6 = new UdpClient(AddressFamily.InterNetworkV6); udp6.Client.DualMode = false; udp6.Client.Bind(new IPEndPoint(IPAddress.IPv6Loopback, port));
        async Task EchoUdp(UdpClient socket) { try { while (!cancel.IsCancellationRequested) { var received = await socket.ReceiveAsync(cancel.Token); await socket.SendAsync(received.Buffer, received.RemoteEndPoint, cancel.Token); } } catch (OperationCanceledException) { } catch (SocketException) { } }
        var echoes = new System.Collections.Concurrent.ConcurrentBag<Task>();
        async Task Echo(TcpClient client) { using (client) { try { var stream = client.GetStream(); var bytes = new byte[8]; while (!cancel.IsCancellationRequested) { int count = await stream.ReadAsync(bytes, cancel.Token); if (count == 0) break; await stream.WriteAsync(bytes.AsMemory(0, count), cancel.Token); } } catch (OperationCanceledException) { } catch (System.IO.IOException) { } } }
        async Task Accept(TcpListener listener) { try { while (!cancel.IsCancellationRequested) { var client = await listener.AcceptTcpClientAsync(cancel.Token); echoes.Add(Echo(client)); } } catch (OperationCanceledException) { } catch (SocketException) { } }
        var listeners = new[] { Accept(v4), Accept(v6), EchoUdp(udp4), EchoUdp(udp6) };
        var rule = new Firewall.Rule { Id = Guid.NewGuid().ToString(), Kind = "onlyApp", Label = "Scoped isolation probe", AppPath = selected, NativeRuleCount = 4 };
        var region = new Firewall.Rule { Id = Guid.NewGuid().ToString(), Kind = "region", Label = "Scoped region range probe", NativeRuleCount = 4 };
        string[] regionRanges = ["127.0.0.0-127.255.255.255", "::1-::1"];
        try
        {
            if (Path.GetFullPath(selected).Equals(Path.GetFullPath(other), StringComparison.OrdinalIgnoreCase) || !File.Exists(selected) || !File.Exists(other)) throw new InvalidOperationException("Choose two different test executables.");
            using (var clean = new NetworkFilters(true)) clean.ApplyRule(rule, [], false, port);
            bool baseline = await Probe(selected, "127.0.0.1", port) && await Probe(other, "127.0.0.1", port) && await Probe(selected, "::1", port) && await Probe(other, "::1", port);
            if (!baseline) throw new InvalidOperationException("The isolated probe baseline did not connect.");
            using (var filter = new NetworkFilters(true)) filter.ApplyRule(rule, [], true, port);
            bool allowedV4 = await Probe(selected, "127.0.0.1", port), deniedV4 = !await Probe(other, "127.0.0.1", port), allowedV6 = await Probe(selected, "::1", port), deniedV6 = !await Probe(other, "::1", port);
            bool udpAllowed = await Probe(selected, "127.0.0.1", port, true) && await Probe(selected, "::1", port, true);
            bool udpDenied = !await Probe(other, "127.0.0.1", port, true) && !await Probe(other, "::1", port, true);
            using (var filter = new NetworkFilters(true)) filter.ApplyRule(rule, [], false, port);
            bool restored = await Probe(other, "127.0.0.1", port) && await Probe(other, "::1", port);
            using var existing = new TcpClient(); await existing.ConnectAsync(IPAddress.Loopback, port);
            async Task<bool> Exchange() { try { using var timeout = new CancellationTokenSource(2000); var stream = existing.GetStream(); await stream.WriteAsync(new byte[] { 0x57 }, timeout.Token); var reply = new byte[1]; return await stream.ReadAsync(reply, timeout.Token) == 1 && reply[0] == 0x57; } catch { return false; } }
            if (!await Exchange()) throw new InvalidOperationException("The existing-connection baseline failed.");
            using (var filter = new NetworkFilters(true)) filter.ApplyRule(region, regionRanges, true, port);
            bool existingTrafficBlocked = !await Exchange();
            bool regionBlocksBothApps = !await Probe(selected, "127.0.0.1", port) && !await Probe(other, "127.0.0.1", port) && !await Probe(selected, "::1", port) && !await Probe(other, "::1", port);
            bool regionBlocksUdp = !await Probe(selected, "127.0.0.1", port, true) && !await Probe(other, "::1", port, true);
            using (var filter = new NetworkFilters(true)) filter.ClearOwned();
            bool regionUnblockRestores = await Probe(selected, "127.0.0.1", port) && await Probe(other, "::1", port);
            region.Kind = "onlyRegion"; region.NativeRuleCount = 2;
            string[] outsideSelection = ["127.0.0.0-127.255.255.255"];
            using (var filter = new NetworkFilters(true)) filter.ApplyRule(region, outsideSelection, true, port, fresh:true);
            bool countryOnlyBlocksOutside = !await Probe(other,"127.0.0.1",port) && !await Probe(selected,"127.0.0.1",port,true);
            bool countryOnlyAllowsSelected = await Probe(other,"::1",port) && await Probe(selected,"::1",port,true);
            using (var filter = new NetworkFilters(true)) filter.ApplyRule(region,outsideSelection,false,port);
            if(!countryOnlyBlocksOutside || !countryOnlyAllowsSelected)throw new InvalidOperationException("Scoped country-only enforcement failed.");
            if (!(allowedV4 && deniedV4 && allowedV6 && deniedV6 && restored && udpAllowed && udpDenied && regionBlocksBothApps && regionBlocksUdp && regionUnblockRestores && existingTrafficBlocked)) throw new InvalidOperationException($"Scoped filter test failed: allowed4={allowedV4}, blocked4={deniedV4}, allowed6={allowedV6}, blocked6={deniedV6}, udpAllowed={udpAllowed}, udpBlocked={udpDenied}, regionBlocks={regionBlocksBothApps}, regionUdp={regionBlocksUdp}, existingTrafficBlocked={existingTrafficBlocked}, restored={restored && regionUnblockRestores}.");
            var bulk = new Firewall.Rule { Id = Guid.NewGuid().ToString(), Kind = "region", Label = "Scoped bulk region probe", NativeRuleCount = 2048 }; var bulkRanges = Enumerable.Repeat("127.0.0.1-127.0.0.1", 1024).ToArray(); var watch = Stopwatch.StartNew();
            try { using (var filter = new NetworkFilters(true)) filter.ApplyRule(bulk, bulkRanges, true, port); watch.Stop(); } finally { using var filter = new NetworkFilters(true); filter.ClearOwned(); }
            Console.WriteLine(JsonSerializer.Serialize(new { passed = true, countryOnlyBlocksOutside, countryOnlyAllowsSelected, allowedV4, deniedV4, allowedV6, deniedV6, udpAllowed, udpDenied, restored, regionBlocksBothApps, regionBlocksUdp, regionUnblockRestores, existingTrafficBlocked, recoveryRemovesOwnedFilters = true, bulkFilters = bulk.NativeRuleCount, bulkApplyMs = watch.ElapsedMilliseconds, scope = "Loopback and one private test port only", persistsAfterEngineClose = true }));
        }
        catch (Exception error) { Console.WriteLine(JsonSerializer.Serialize(new { passed = false, error = error.Message })); Environment.ExitCode = 1; }
        finally { using (var filter = new NetworkFilters(true)) { filter.ApplyRule(rule, [], false, port); filter.ApplyRule(region, regionRanges, false, port); } cancel.Cancel(); v4.Stop(); v6.Stop(); await Task.WhenAll(listeners); await Task.WhenAll(echoes); }
    }
}

