using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

// Only filters in Watchmen's own sublayer are ever replaced or removed. Other providers,
// Windows firewall defaults and existing allow rules are left to Windows.
sealed class NetworkFilters : IDisposable
{
    static readonly Guid ProductionSubLayer = new("094e47d5-c6a2-48e5-a183-59798bca9da1");
    static readonly Guid TestingSubLayer = new("1d91eb73-2fe0-43b9-9f13-8297f1b2c660");
    Guid SubLayerKey => testScope ? TestingSubLayer : ProductionSubLayer;
    static readonly Guid AppId = new("d78e1e87-8644-4ea5-9437-d809ecefc971");
    static readonly Guid RemoteIp = new("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    static readonly Guid RemotePort = new("c35a604d-d22b-4e1a-91b4-68f674ee674b");
    static readonly Guid[] Layers = [new("c38d57d1-05a7-4c33-904f-7fbceee60e82"), new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4"), new("e1cd9fe7-f4b5-4273-96c0-592e487b8650"), new("a3b42c97-9f04-4672-b87e-cee9c483257f")];
    internal static readonly Guid RuleId = new("375e9c3b-f765-4404-94cb-0912b6464d15");
    readonly IntPtr engine;
    readonly bool testScope;

    public NetworkFilters(bool testScope = false)
    {
        this.testScope = testScope;
        var session = new Session { transactionWait = 15000 };
        Check(FwpmEngineOpen0(null, 10, IntPtr.Zero, ref session, out engine));
    }
    static void Check(uint code) { if (code != 0) throw new InvalidOperationException($"Windows filtering failed (0x{code:X8})."); }
    public void Dispose() { FwpmEngineClose0(engine); }

    Guid RuleKey(string id, int index) => new(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes("Watchmen.NetworkRules.v1/" + (testScope ? "test/" : "") + id + "/" + index)).AsSpan(0, 16));
    public Firewall.Rule? Master(Firewall.Rule rule)
    {
        var key = RuleKey(rule.Id, 0); uint code = FwpmFilterGetByKey0(engine, ref key, out var pointer); if (code == 0x80320003) return null; Check(code);
        try { var filter = Marshal.PtrToStructure<Filter>(pointer); if (filter.subLayerKey != SubLayerKey || filter.providerData.size is 0 or > 16384) return null; var bytes = new byte[filter.providerData.size]; Marshal.Copy(filter.providerData.data, bytes, 0, bytes.Length); var actual = JsonSerializer.Deserialize<Firewall.Rule>(bytes, Firewall.Json); return actual?.Id == rule.Id ? actual : null; } finally { FwpmFreeMemory0(ref pointer); }
    }
    public (bool enabled, bool partial) RuleState(Firewall.Rule rule)
    {
        // Our writes are transactional. Check both ends, and every filter for
        // small rules, to detect missing externally edited policy objects.
        int[] indices = rule.NativeRuleCount <= 4 ? Enumerable.Range(0, rule.NativeRuleCount).ToArray() : [0, rule.NativeRuleCount - 1];
        int found = 0, active = 0; bool persistent = true;
        foreach (int index in indices) { var key = RuleKey(rule.Id, index); uint result = FwpmFilterGetByKey0(engine, ref key, out var pointer); if (result == 0x80320003) continue; Check(result); try { var filter = Marshal.PtrToStructure<Filter>(pointer); if (filter.subLayerKey != SubLayerKey) throw new InvalidOperationException("A network rule key belongs to another policy."); found++; if ((filter.flags & 0x20) == 0) active++; if ((filter.flags & 1) == 0) persistent = false; } finally { FwpmFreeMemory0(ref pointer); } }
        return (active > 0, !persistent || found != active || found > 0 && found != indices.Length);
    }
    static bool Version4(string range) => IPAddress.Parse(range.Split('-', '/')[0]).AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
    public void ApplyRule(Firewall.Rule rule, string[] ranges, bool enabled, int testPort = 0, bool fresh = false)
    {
        IntPtr application = IntPtr.Zero, conditions = IntPtr.Zero, address = IntPtr.Zero, metadata = IntPtr.Zero;
        var allocations = new List<IntPtr>();
        bool transaction = false;
        IntPtr Allocate(int size) { var pointer = Marshal.AllocHGlobal(size); allocations.Add(pointer); return pointer; }
        Value IpValue(string ip)
        {
            var parsed = IPAddress.Parse(ip); var bytes = parsed.GetAddressBytes();
            if (bytes.Length == 4) return new Value { type = 3, pointer = (IntPtr)(long)System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(bytes) };
            var pointer = Allocate(16); Marshal.Copy(bytes, 0, pointer, 16); return new Value { type = 11, pointer = pointer };
        }
        Condition AddressCondition(string range)
        {
            var parts = range.Split('-');
            if (parts.Length == 2) { var pointer = Allocate(32); Marshal.StructureToPtr(IpValue(parts[0]), pointer, false); Marshal.StructureToPtr(IpValue(parts[1]), pointer + 16, false); return new Condition { key = RemoteIp, match = 5, value = new Value { type = 258, pointer = pointer } }; }
            var prefix = range.Split('/');
            if (prefix.Length == 2) { var ip = IPAddress.Parse(prefix[0]); int bits = int.Parse(prefix[1]); var bytes = ip.GetAddressBytes(); var pointer = Allocate(17); if (bytes.Length == 4) { Marshal.WriteInt32(pointer, unchecked((int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(bytes))); Marshal.WriteInt32(pointer, 4, unchecked((int)(uint.MaxValue << (32 - bits)))); } else { Marshal.Copy(bytes, 0, pointer, 16); Marshal.WriteByte(pointer, 16, (byte)bits); } return new Condition { key = RemoteIp, value = new Value { type = bytes.Length == 4 ? 256u : 257u, pointer = pointer } }; }
            return new Condition { key = RemoteIp, value = IpValue(range) };
        }
        try
        {
            PolicyOperation.Check();
            PolicyOperation.Report("waiting-windows",0,0,"Waiting for Windows filtering engine…");
            Check(FwpmTransactionBegin0(engine, 0)); transaction = true;
            int count = rule.NativeRuleCount;
            for (int index = 0; !fresh && index < count; index++)
            {
                PolicyOperation.Check();
                PolicyOperation.Report("removing",index,count,"Removing previous filters…");
                var key = RuleKey(rule.Id, index); uint result = FwpmFilterGetByKey0(engine, ref key, out var prior);
                if (result == 0) { try { var filter = Marshal.PtrToStructure<Filter>(prior); if (filter.subLayerKey != SubLayerKey) throw new InvalidOperationException("A network rule key belongs to another policy."); } finally { FwpmFreeMemory0(ref prior); } Check(FwpmFilterDeleteByKey0(engine, ref key)); } else if (result != 0x80320003) Check(result);
            }
            if (enabled)
            {
                if (testScope && testPort is < 1 or > 65535) throw new InvalidOperationException("An isolated test port is required.");
                var subLayer = new SubLayer { key = SubLayerKey, display = new Display { name = "Watchmen network rules" }, flags = 1, weight = 0xfffe }; uint added = FwpmSubLayerAdd0(engine, ref subLayer, IntPtr.Zero); if (added != 0x80320009) Check(added);
                if (rule.Kind is "app" or "connection" or "onlyApp") Check(FwpmGetAppIdFromFileName0(rule.AppPath, out application));
                int size = Marshal.SizeOf<Condition>(); conditions = Marshal.AllocHGlobal(size * 6);
                byte[] data = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(rule, Firewall.Json)); metadata = Marshal.AllocHGlobal(data.Length); Marshal.Copy(data, 0, metadata, data.Length);
                var targets = rule.Kind is "region" or "onlyRegion" ? ranges : rule.Kind is "destination" or "connection" ? [rule.Address] : new[] { "" }; int sequence = 0;
                foreach (string target in targets)
                {
                    var layerIndices = target.Length == 0 ? new[] { 0, 1, 2, 3 } : Version4(target) ? new[] { 0, 2 } : new[] { 1, 3 };
                    foreach (int layer in layerIndices)
                    {
                        PolicyOperation.Check();
                        PolicyOperation.Report("staging",sequence,count,"Staging persistent Windows filters…");
                        int number = 0;
                        void Add(Condition condition) { Marshal.StructureToPtr(condition, conditions + number * size, false); number++; }
                        if (application != IntPtr.Zero) Add(new Condition { key = AppId, match = rule.Kind == "onlyApp" ? 10u : 0u, value = new Value { type = 12, pointer = application } });
                        if (target.Length > 0) Add(AddressCondition(target));
                        if (testScope)
                        {
                            if (target.Length == 0) Add(AddressCondition(layer % 2 == 0 ? "127.0.0.1" : "::1"));
                            else if (target.Split('-', '/').Where(part => part.Contains('.') || part.Contains(':')).Any(part => !IPAddress.IsLoopback(IPAddress.Parse(part)))) throw new InvalidOperationException("Test ranges must stay on loopback.");
                            Add(new Condition { key = RemotePort, value = new Value { type = 2, pointer = (IntPtr)testPort } });
                        }
                        if (rule.Kind == "connection")
                        {
                            Add(new Condition { key = RemotePort, value = new Value { type = 2, pointer = (IntPtr)rule.Port } });
                            Add(new Condition { key = new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7"), value = new Value { type = 1, pointer = (IntPtr)(rule.Protocol == "TCP" ? 6 : 17) } });
                        }
                        var filter = new Filter { key = RuleKey(rule.Id, sequence), display = new Display { name = "Watchmen:" + rule.Id, description = rule.Kind + " · " + rule.Label }, flags = 1, providerData = sequence == 0 ? new Blob { size = (uint)data.Length, data = metadata } : default, layerKey = Layers[layer], subLayerKey = SubLayerKey, conditionCount = (uint)number, conditions = conditions, action = new Action { type = 0x1001 } };
                        Check(FwpmFilterAdd0(engine, ref filter, IntPtr.Zero, out _)); sequence++;
                        foreach (var pointer in allocations) Marshal.FreeHGlobal(pointer); allocations.Clear();
                    }
                }
                if (sequence != count) throw new InvalidOperationException("The rule filter count does not match its scope.");
            }
            PolicyOperation.Check();
            PolicyOperation.Report("committing",0,0,"Windows is committing the rules. Monitoring remains available.",false);
            Check(FwpmTransactionCommit0(engine)); transaction = false;
        }
        finally
        {
            if (transaction) { PolicyOperation.Report("rolling-back",0,0,"Rolling back uncommitted changes…",false); FwpmTransactionAbort0(engine); }
            if (application != IntPtr.Zero) FwpmFreeMemory0(ref application);
            if (conditions != IntPtr.Zero) Marshal.FreeHGlobal(conditions);
            if (address != IntPtr.Zero) Marshal.FreeHGlobal(address);
            if (metadata != IntPtr.Zero) Marshal.FreeHGlobal(metadata);
            foreach (var pointer in allocations) Marshal.FreeHGlobal(pointer);
        }
    }
    public void ClearOwned()
    {
        Check(FwpmFilterCreateEnumHandle0(engine, IntPtr.Zero, out var enumeration));
        var ids = new List<ulong>();
        try { while (true) { PolicyOperation.Check(); PolicyOperation.Report("finding",ids.Count,0,"Finding Watchmen filters…"); Check(FwpmFilterEnum0(engine, enumeration, 1024, out var entries, out uint count)); try { if (count == 0) break; for (int i = 0; i < count; i++) { var filter = Marshal.PtrToStructure<Filter>(Marshal.ReadIntPtr(entries, i * IntPtr.Size)); if (filter.subLayerKey == SubLayerKey) ids.Add(filter.id); } } finally { if (entries != IntPtr.Zero) FwpmFreeMemory0(ref entries); } } } finally { FwpmFilterDestroyEnumHandle0(engine, enumeration); }
        Check(FwpmTransactionBegin0(engine, 0)); bool committed = false;
        try { int removed=0; foreach (var id in ids) { PolicyOperation.Check(); PolicyOperation.Report("removing",removed++,ids.Count,"Removing Watchmen filters…"); uint code = FwpmFilterDeleteById0(engine, id); if (code != 0x80320003) Check(code); } PolicyOperation.Check(); PolicyOperation.Report("committing",0,0,"Windows is committing the removal…",false); Check(FwpmTransactionCommit0(engine)); committed = true; } finally { if (!committed) FwpmTransactionAbort0(engine); }
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct Display { [MarshalAs(UnmanagedType.LPWStr)] public string? name; [MarshalAs(UnmanagedType.LPWStr)] public string? description; }
    [StructLayout(LayoutKind.Sequential)] struct Blob { public uint size; public IntPtr data; }
    [StructLayout(LayoutKind.Explicit, Size = 16)] struct Value { [FieldOffset(0)] public uint type; [FieldOffset(8)] public IntPtr pointer; }
    [StructLayout(LayoutKind.Sequential)] struct Condition { public Guid key; public uint match; public Value value; }
    [StructLayout(LayoutKind.Sequential)] struct Action { public uint type; public Guid key; }
    [StructLayout(LayoutKind.Sequential)] struct SubLayer { public Guid key; public Display display; public uint flags; public IntPtr provider; public Blob providerData; public ushort weight; }
    [StructLayout(LayoutKind.Sequential)] struct Filter { public Guid key; public Display display; public uint flags; public IntPtr provider; public Blob providerData; public Guid layerKey; public Guid subLayerKey; public Value weight; public uint conditionCount; public IntPtr conditions; public Action action; public ulong context1, context2; public IntPtr reserved; public ulong id; public Value effectiveWeight; }
    [StructLayout(LayoutKind.Sequential)] struct Session { public Guid key; public Display display; public uint flags, transactionWait, processId; public IntPtr sid, username; public int kernelMode; }
    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)] static extern uint FwpmEngineOpen0(string? server, uint auth, IntPtr identity, ref Session session, out IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionBegin0(IntPtr engine, uint flags);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionCommit0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionAbort0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerAdd0(IntPtr engine, ref SubLayer layer, IntPtr security);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterAdd0(IntPtr engine, ref Filter filter, IntPtr security, out ulong id);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterGetByKey0(IntPtr engine, ref Guid key, out IntPtr filter);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr engine, ref Guid key);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteById0(IntPtr engine, ulong id);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterCreateEnumHandle0(IntPtr engine, IntPtr template, out IntPtr enumeration);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterEnum0(IntPtr engine, IntPtr enumeration, uint requested, out IntPtr entries, out uint count);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engine, IntPtr enumeration);
    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)] static extern uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);
    [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr pointer);
}


