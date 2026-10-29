using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.RegularExpressions;

static class Firewall
{
    internal static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, PropertyNameCaseInsensitive = true };
    static readonly string Root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WatchmenNetworkMonitor");
    static readonly string Store = Path.Combine(Root, "Rules");
    internal sealed class Rule
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Kind { get; set; } = "";
        public string Label { get; set; } = "";
        public string AppPath { get; set; } = "";
        public string Address { get; set; } = "";
        public string Protocol { get; set; } = "";
        public int Port { get; set; }
        public string[] Countries { get; set; } = [];
        public string SourceMonth { get; set; } = "";
        public int RangeCount { get; set; }
        public int NativeRuleCount { get; set; }
        public bool Enabled { get; set; } = true;
        public bool Partial { get; set; }
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    }
    sealed class Record { public int Version { get; set; } = 1; public Rule Rule { get; set; } = new(); public string[] Ranges { get; set; } = []; }
    sealed class Request { public string Action { get; set; } = "list"; public Rule? Rule { get; set; } public string Id { get; set; } = ""; public bool Enabled { get; set; } public string[] Ranges { get; set; } = []; }
    static bool Admin => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
    static string FileName(string id) => Path.Combine(Store, Guid.Parse(id).ToString() + ".json");
    static void SecureStore()
    {
        // This is machine policy. Administrators/System can modify it; ordinary
        // users can inspect it. Never follow reparse points in the policy path.
        foreach (string folder in new[] { Root, Store })
        {
            Directory.CreateDirectory(folder);
            if ((File.GetAttributes(folder) & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("The network policy folder must not be a link or junction.");
            var security = new DirectorySecurity(); security.SetAccessRuleProtection(true, false);
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            security.SetOwner(admins);
            foreach (var pair in new[] { (admins, FileSystemRights.FullControl), (new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl), (new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.ReadAndExecute) })
                security.AddAccessRule(new FileSystemAccessRule(pair.Item1, pair.Item2, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(folder).SetAccessControl(security);
        }
    }
    static void Save(Record record)
    {
        string filename = FileName(record.Rule.Id), temporary = Path.Combine(Store, Guid.NewGuid() + ".tmp");
        try { File.WriteAllText(temporary, JsonSerializer.Serialize(record, Json)); File.Move(temporary, filename, true); }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    static int FilterCount(Rule rule, string[] ranges) => rule.Kind is "app" or "onlyApp" ? 4 : rule.Kind == "region" ? checked(ranges.Length * 2) : 2;
    static Record Load(string id)
    {
        var file = new FileInfo(FileName(id));
        if (!file.Exists) throw new InvalidOperationException("This Watchmen rule is no longer available.");
        if (file.Length > 16 * 1024 * 1024 || (file.Attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("The saved policy record is invalid. Unblock all Watchmen rules to remove restrictions.");
        var record = JsonSerializer.Deserialize<Record>(File.ReadAllText(file.FullName), Json) ?? throw new InvalidOperationException("The saved rule is unreadable.");
        if (record.Version != 1 || record.Rule.Id != Guid.Parse(id).ToString() || record.Ranges.Length > 250000 || !new[] { "app", "connection", "destination", "region", "onlyApp" }.Contains(record.Rule.Kind)) throw new InvalidOperationException("The saved rule has an unsupported format.");
        record.Rule.NativeRuleCount = FilterCount(record.Rule, record.Ranges);
        if (record.Rule.NativeRuleCount < 1) throw new InvalidOperationException("The saved rule has no filter scope.");
        return record;
    }
    static List<Record> Records()
    {
        if (!Directory.Exists(Store)) return [];
        if ((File.GetAttributes(Root) & FileAttributes.ReparsePoint) != 0 || (File.GetAttributes(Store) & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("The policy folder must not be a link or junction.");
        var files = Directory.GetFiles(Store, "*.json");
        if (files.Length > 1000) throw new InvalidOperationException("The policy store exceeds 1,000 rules. Unblock all Watchmen rules before repairing it.");
        return files.Select(Path.GetFileNameWithoutExtension).Where(id => Guid.TryParse(id, out _)).Select(id => Load(id!)).ToList();
    }
    internal static object Status()
    {
        bool verified = true; string? error = null; List<Record> records;
        try { records = Records(); } catch (Exception e) { records = []; verified = false; error = e.Message; }
        var rules = records.Select(r => r.Rule).ToList();
        try
        {
            using var engine = new NetworkFilters();
            foreach (var rule in rules.ToArray())
            {
                var actual = engine.RuleState(rule); if (rule.Enabled && !actual.enabled) actual.partial = true; rule.Enabled = actual.enabled; rule.Partial = actual.partial;
                var authoritative = engine.Master(rule);
                if (authoritative != null) { int index = rules.IndexOf(rule); authoritative.Enabled = actual.enabled; authoritative.Partial = actual.partial; rules[index] = authoritative; }
            }
        }
        catch { verified = false; error ??= "Windows filter state could not be verified. Saved state is shown. Restart as administrator or check the Base Filtering Engine service."; }
        var profiles = new List<object>();
        try { dynamic policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")!)!; foreach (int p in new[] { 1, 2, 4 }) profiles.Add(new { profile = p, enabled = (bool)policy.FirewallEnabled[p] }); } catch { }
        return new { rules = rules.OrderByDescending(r => r.Enabled).ThenByDescending(r => r.CreatedAt), admin = Admin, profiles, isolationVerified = verified, verificationError = error, storagePath = Store, enforcement = "Windows Filtering Platform", updatedAt = DateTimeOffset.UtcNow };
    }
    static void Validate(Rule rule, string[] ranges)
    {
        if (!new[] { "app", "connection", "destination", "region", "onlyApp" }.Contains(rule.Kind)) throw new InvalidOperationException("Choose an app, endpoint, region, or app isolation rule.");
        if (rule.Label.Length is 0 or > 160 || rule.AppPath.Length > 4096) throw new InvalidOperationException("The rule label or executable path is too long.");
        if (rule.Kind is "app" or "connection" or "onlyApp")
        {
            if (!Path.IsPathFullyQualified(rule.AppPath) || !Path.GetExtension(rule.AppPath).Equals(".exe", StringComparison.OrdinalIgnoreCase) || !File.Exists(rule.AppPath)) throw new InvalidOperationException("Select an existing .exe file. The executable may have been removed or moved.");
            rule.AppPath = Path.GetFullPath(rule.AppPath);
        }
        if (rule.Kind is "connection" or "destination")
        {
            if (!IPAddress.TryParse(rule.Address, out var address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) throw new InvalidOperationException("Choose a specific remote address.");
            rule.Address = address.ToString();
        }
        if (rule.Kind == "connection" && (rule.Port is < 1 or > 65535 || !new[] { "TCP", "UDP" }.Contains(rule.Protocol))) throw new InvalidOperationException("Choose a remote TCP or UDP port.");
        if (rule.Kind == "region")
        {
            if (rule.Countries.Length is 0 or > 250 || rule.Countries.Any(c => !Regex.IsMatch(c, "^[A-Z]{2}$")) || !Regex.IsMatch(rule.SourceMonth, "^20[0-9]{2}-(0[1-9]|1[0-2])$")) throw new InvalidOperationException("Choose valid countries and a dated range dataset.");
            if (ranges.Length is 0 or > 250000) throw new InvalidOperationException("Choose between one and 250,000 address ranges.");
            foreach (string range in ranges)
            {
                var parts = range.Split('-');
                if (parts.Length == 2)
                {
                    if (!IPAddress.TryParse(parts[0], out var first) || !IPAddress.TryParse(parts[1], out var last) || first.AddressFamily != last.AddressFamily || new System.Numerics.BigInteger(first.GetAddressBytes(), true, true) > new System.Numerics.BigInteger(last.GetAddressBytes(), true, true)) throw new InvalidOperationException("The country data contains an invalid IP range.");
                }
                else if (parts.Length != 1 || !IPAddress.TryParse(range, out _))
                {
                    var prefix = range.Split('/');
                    if (prefix.Length != 2 || !IPAddress.TryParse(prefix[0], out var ip) || !int.TryParse(prefix[1], out var bits) || bits < 1 || bits > (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128)) throw new InvalidOperationException("The country data contains an invalid IP prefix.");
                }
            }
            rule.RangeCount = ranges.Length;
        }
        rule.NativeRuleCount = FilterCount(rule, ranges);
    }
    static void SetEnabled(string id, bool enabled)
    {
        var record = Load(id);
        if (enabled) Validate(record.Rule, record.Ranges);
        using var engine = new NetworkFilters(); engine.ApplyRule(record.Rule, record.Ranges, enabled);
        record.Rule.Enabled = enabled; record.Rule.Partial = false; Save(record);
    }
    static void Add(Rule rule, string[] ranges)
    {
        Validate(rule, ranges);
        var existing = Records().FirstOrDefault(r => r.Rule.Kind == rule.Kind && r.Rule.AppPath.Equals(rule.AppPath, StringComparison.OrdinalIgnoreCase) && r.Rule.Address == rule.Address && r.Rule.Protocol == rule.Protocol && r.Rule.Port == rule.Port && r.Rule.Countries.Order().SequenceEqual(rule.Countries.Order()));
        if (existing != null) {
            if(rule.Kind=="region"&&(existing.Rule.SourceMonth!=rule.SourceMonth||!existing.Ranges.SequenceEqual(ranges)))throw new InvalidOperationException("A saved block for these countries uses a different snapshot. Unblock and remove it before applying this new review.");
            SetEnabled(existing.Rule.Id, true); return;
        }
        rule.Id = rule.Kind == "onlyApp" ? NetworkFilters.RuleId.ToString() : Guid.NewGuid().ToString();
        rule.CreatedAt = DateTimeOffset.UtcNow; rule.Enabled = true;
        if (Records().Count >= 1000 && !File.Exists(FileName(rule.Id))) throw new InvalidOperationException("Remove an unused saved rule before adding more than 1,000 rules.");
        Record? previous = File.Exists(FileName(rule.Id)) ? Load(rule.Id) : null;
        var record = new Record { Rule = rule, Ranges = ranges };
        // Record recovery data before touching BFE. An interrupted WFP
        // transaction rolls back automatically; status reads committed filters.
        Save(record);
        try { using var engine = new NetworkFilters(); engine.ApplyRule(rule, ranges, true); }
        catch { try { if (previous != null) Save(previous); else File.Delete(FileName(rule.Id)); } catch { } throw; }
    }
    public static async Task Run(bool reset = false)
    {
        try
        {
            Request request;
            if (reset) request = new Request { Action = "unblock-all" };
            else
            {
                string input = await Console.In.ReadToEndAsync();
                if (input.Length > 16 * 1024 * 1024) throw new InvalidOperationException("The request exceeds the 16 MB size limit.");
                request = JsonSerializer.Deserialize<Request>(input, Json) ?? throw new InvalidOperationException("No rule was supplied.");
            }
            if (request.Action == "list") { Console.WriteLine(JsonSerializer.Serialize(new { ok = true, value = Status() }, Json)); return; }
            using var mutex = new Mutex(false, "Global\\Watchmen.NetworkRules.v1"); bool held = false;
            try
            {
                try { held = mutex.WaitOne(TimeSpan.FromSeconds(60)); } catch (AbandonedMutexException) { held = true; }
                if (!held) throw new InvalidOperationException("Another Watchmen window is updating rules. Try shortly.");
                if (request.Action != "list")
                {
                    if (!Admin) throw new InvalidOperationException("Restart Watchmen as administrator to change network rules.");
                    if (request.Action == "unblock-all")
                    {
                        // Recovery does not depend on a readable metadata store.
                        using (var engine = new NetworkFilters()) engine.ClearOwned();
                        SecureStore();
                        foreach (string file in Directory.GetFiles(Store, "*.json")) try { var record = Load(Path.GetFileNameWithoutExtension(file)); record.Rule.Enabled = false; record.Rule.Partial = false; Save(record); } catch { }
                    }
                    else
                    {
                        SecureStore();
                        if (request.Action == "add") Add(request.Rule ?? throw new InvalidOperationException("No rule supplied."), request.Ranges);
                        else if (request.Action == "set-enabled") SetEnabled(request.Id, request.Enabled);
                        else if (request.Action == "forget") { var record = Load(request.Id); using (var engine = new NetworkFilters()) engine.ApplyRule(record.Rule, record.Ranges, false); File.Delete(FileName(record.Rule.Id)); }
                        else throw new InvalidOperationException("Unsupported network-rule action.");
                    }
                }
                Console.WriteLine(JsonSerializer.Serialize(new { ok = true, value = Status() }, Json));
            }
            finally { if (held) mutex.ReleaseMutex(); }
        }
        catch (Exception error)
        {
            string message = error is InvalidOperationException ? error.Message : $"Windows could not update the rule (0x{error.HResult:X8}). Refresh rules to check committed state; unrelated Windows policies were not changed.";
            Console.WriteLine(JsonSerializer.Serialize(new { ok = false, error = message }, Json)); Environment.ExitCode = 1;
        }
    }
}

