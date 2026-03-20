namespace SCAScanner;

using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;

/// <summary>
/// Writes scan results in SCAP-SCC log format.
/// Implements only <see cref="IPolicyReporter"/> and <see cref="ICheckReporter"/> —
/// collects data during scan and writes the file on disposal.
/// </summary>
public sealed class AdvancedReporter : IPolicyReporter, ICheckReporter, IDisposable
{
    // 28 spaces aligns continuation lines with the value column (label padded to 28 + ": ")
    private static readonly string Continuation = new(' ', 28);

    private readonly string _filePath;
    private readonly string _hostname;
    private readonly string _os;
    private readonly string _osVersion;
    private readonly string _processorName;
    private readonly string _processorArch;
    private readonly long   _totalMemoryMb;
    private readonly IReadOnlyList<InterfaceEntry> _interfaces;
    private readonly DateTime _scanStart;

    private record InterfaceEntry(string Label, string IpAddress, string MacAddress);

    private string _policyName = string.Empty;
    private string _policyId   = string.Empty;

    private record CheckEntry(
        Check Check,
        CheckResult Result,
        List<ParsedRule> ParsedRules,
        IReadOnlyList<RuleResult> RuleResults);

    private readonly List<CheckEntry> _entries = new();

    // Temporary accumulation between PrintRuleExplanations/PrintRuleResults and PrintCheckResult
    private List<ParsedRule> _pendingParsedRules = [];
    private IReadOnlyList<RuleResult> _pendingRuleResults = [];

    public AdvancedReporter(string filePath)
    {
        _filePath      = filePath;
        _scanStart     = DateTime.Now;
        _hostname      = TryGetFqdn();
        _os            = RuntimeInformation.OSDescription;
        _osVersion     = Environment.OSVersion.Version.ToString();
        _processorName = GetProcessorName();
        _processorArch = RuntimeInformation.ProcessArchitecture.ToString();
        _totalMemoryMb = (long)(GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / (1024 * 1024));
        _interfaces    = GetNetworkInterfaces();
    }

    // ── IPolicyReporter ───────────────────────────────────────────────────

    public void PrintBanner() { }
    public void PrintHelp()   { }

    public void PrintPolicyHeader(SCAPolicy policy, string platform)
    {
        _policyName = policy.Policy.Name;
        _policyId   = policy.Policy.Id;
    }

    public void PrintRequirementsSection(Check requirementsCheck, PolicyVariables? variables, CheckResult requirementsResult) { }

    // ── ICheckReporter ────────────────────────────────────────────────────

    public void PrintCheckHeader(Check check) { }

    public void PrintRuleExplanations(List<ParsedRule> parsedRules, Check check, PolicyVariables? variables)
    {
        _pendingParsedRules = parsedRules;
    }

    public void PrintRuleResults(IReadOnlyList<RuleResult> ruleResults)
    {
        _pendingRuleResults = ruleResults;
    }

    public void PrintCheckResult(Check check, CheckResult result, int totalPassed, int totalFailed)
    {
        _entries.Add(new CheckEntry(check, result, _pendingParsedRules, _pendingRuleResults));
        _pendingParsedRules = [];
        _pendingRuleResults = [];
    }

    // ── IDisposable ───────────────────────────────────────────────────────

    public void Dispose()
    {
        DateTime scanEnd = DateTime.Now;
        TimeSpan duration = scanEnd - _scanStart;

        int passed  = _entries.Count(e => e.Result.Status == CheckStatus.Passed);
        int failed  = _entries.Count(e => e.Result.Status == CheckStatus.Failed);
        int invalid = _entries.Count(e => e.Result.Status == CheckStatus.Invalid);
        int total   = passed + failed + invalid;
        double score = total > 0 ? Math.Round(passed * 100.0 / total, 2) : 0;
        string scoreStr = $"{score.ToString("F2", CultureInfo.InvariantCulture)}%";

        var sb = new StringBuilder();

        // ── Header ────────────────────────────────────────────────────────
        sb.AppendLine("SCA Compliance Checker");
        sb.AppendLine($"All Settings Report - {_policyName}");

        // ── Score ─────────────────────────────────────────────────────────
        sb.AppendLine();
        sb.AppendLine("========== Score =====================================================");
        sb.AppendLine();
        sb.AppendLine(F("Adjusted Score", scoreStr));
        sb.AppendLine(F("Original Score", scoreStr));
        sb.AppendLine(F("Counts", $"[Pass] {passed}"));
        sb.AppendLine($"{Continuation}: [Fail] {failed}");
        sb.AppendLine($"{Continuation}: [Error] {invalid}");
        sb.AppendLine($"{Continuation}: [Total] {total}");

        // ── System Information ────────────────────────────────────────────
        sb.AppendLine();
        sb.AppendLine("========== System Information ========================================");
        sb.AppendLine();
        sb.AppendLine(F("Target Hostname", _hostname));
        sb.AppendLine(F("Operating System", _os));
        sb.AppendLine(F("OS Version", _osVersion));
        sb.AppendLine(F("Processor", _processorName));
        sb.AppendLine(F("Processor Architecture", _processorArch));
        sb.AppendLine(F("Physical Memory", $"{_totalMemoryMb} mb"));
        foreach (InterfaceEntry iface in _interfaces)
        {
            sb.AppendLine(F("Interfaces", iface.Label));
            sb.AppendLine(F("   IP Address", iface.IpAddress));
            sb.AppendLine(F("   MAC Address", iface.MacAddress));
        }

        // ── Content Information ───────────────────────────────────────────
        sb.AppendLine();
        sb.AppendLine("========== Content Information =======================================");
        sb.AppendLine();
        sb.AppendLine(F("Stream", _policyId));
        sb.AppendLine(F("Profile", $"Id: {_policyId}"));
        sb.AppendLine(F("Start Time", _scanStart.ToString("yyyy-MM-ddTHH:mm:ss")));
        sb.AppendLine(F("End Time", scanEnd.ToString("yyyy-MM-ddTHH:mm:ss")));
        sb.AppendLine(F("Scan Duration", duration.ToString(@"hh\:mm\:ss")));
        sb.AppendLine(F("Scanner", "SCA Scanner"));
        sb.AppendLine(F("Identity", _hostname));

        // ── Automated Checks ──────────────────────────────────────────────
        sb.AppendLine();
        sb.AppendLine();
        sb.AppendLine("==========   Automated Checks   ======================================");
        sb.AppendLine();
        foreach (CheckEntry entry in _entries)
            sb.AppendLine($"V-{entry.Check.Id} - {entry.Check.Title} - {MapStatus(entry.Result.Status)}");

        // ── Detailed Results ──────────────────────────────────────────────
        sb.AppendLine();
        sb.AppendLine();
        sb.AppendLine("========== Detailed Results ==========================================");

        for (int ei = 0; ei < _entries.Count; ei++)
        {
            CheckEntry entry = _entries[ei];
            Check check = entry.Check;
            CheckResult result = entry.Result;

            sb.AppendLine();
            sb.AppendLine(F("Title", $"V-{check.Id} - {check.Title}"));
            sb.AppendLine(F("Rule ID", $"sca_rule_{_policyId}_{check.Id}_rule"));
            sb.AppendLine(F("Test Type", "Automated"));
            sb.AppendLine(F("Rule Result", MapStatus(result.Status)));
            sb.AppendLine(F("Condition", result.Reason));
            if (!string.IsNullOrWhiteSpace(check.Description))
                sb.AppendLine(FMultiline("Description", check.Description));
            if (!string.IsNullOrWhiteSpace(check.Remediation))
                sb.AppendLine(FMultiline("Fix Text", check.Remediation));

            // ── Per-rule test blocks ──────────────────────────────────────
            if (entry.ParsedRules.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("---");

                for (int ri = 0; ri < entry.ParsedRules.Count; ri++)
                {
                    ParsedRule parsedRule = entry.ParsedRules[ri];
                    sb.AppendLine();
                    sb.AppendLine(FMultiline("Test", $"[{ri + 1}] {RuleParser.Explain(parsedRule)}"));
                    sb.AppendLine(F("Raw Rule", parsedRule.OriginalText));

                    if (ri < entry.RuleResults.Count)
                    {
                        RuleResult rr = entry.RuleResults[ri];
                        string ruleStatus = rr.Invalid ? "Invalid" : rr.Passed ? "Pass" : "Fail";
                        sb.AppendLine(F("Result", ruleStatus));
                        sb.AppendLine(FMultiline("Detail", rr.Detail));
                    }

                    if (ri < entry.ParsedRules.Count - 1)
                    {
                        sb.AppendLine();
                        sb.AppendLine("---");
                    }
                }
            }

            sb.AppendLine();
            sb.AppendLine("------------------------------");
        }

        try
        {
            File.WriteAllText(_filePath, sb.ToString(), Encoding.UTF8);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"ScapSccReporter: failed to write '{_filePath}': {ex.Message}");
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /// <summary>Format a single-line label+value pair with label padded to 28 chars.</summary>
    private static string F(string label, string value) => $"{label,-28}: {value}";

    /// <summary>
    /// Format a possibly multi-line field. Continuation lines are indented with
    /// 30 spaces to align under the value column.
    /// </summary>
    private static string FMultiline(string label, string value)
    {
        string[] lines = value.Replace("\r\n", "\n").Split('\n');
        var sb = new StringBuilder();
        sb.Append(F(label, lines[0].TrimEnd()));
        for (int i = 1; i < lines.Length; i++)
        {
            if (string.IsNullOrWhiteSpace(lines[i])) continue;
            sb.AppendLine();
            sb.Append($"{Continuation}: {lines[i]}");
        }
        return sb.ToString();
    }

    private static string MapStatus(CheckStatus status) => status switch
    {
        CheckStatus.Passed  => "Pass",
        CheckStatus.Failed  => "Fail",
        CheckStatus.Invalid => "Not Applicable",
        _                   => "Unknown"
    };

    private static string TryGetFqdn()
    {
        try { return Dns.GetHostEntry("").HostName; }
        catch { return Environment.MachineName; }
    }

    private static string GetProcessorName()
    {
        try
        {
            if (OperatingSystem.IsMacOS())
            {
                string name = RunCommand("sysctl", ["-n", "machdep.cpu.brand_string"]).Trim();
                if (!string.IsNullOrEmpty(name)) return name;
            }
            else if (OperatingSystem.IsLinux())
            {
                foreach (string line in File.ReadLines("/proc/cpuinfo"))
                {
                    if (!line.StartsWith("model name", StringComparison.OrdinalIgnoreCase)) continue;
                    int colon = line.IndexOf(':');
                    if (colon >= 0) return line[(colon + 1)..].Trim();
                }
            }
            else if (OperatingSystem.IsWindows())
            {
                string name = RunCommand("wmic", ["cpu", "get", "name", "/value"]);
                foreach (string line in name.Split('\n'))
                {
                    if (line.StartsWith("Name=", StringComparison.OrdinalIgnoreCase))
                        return line[5..].Trim();
                }
            }
        }
        catch { /* fall through */ }
        return RuntimeInformation.ProcessArchitecture.ToString();
    }

    private static string RunCommand(string command, string[] args)
    {
        try
        {
            using var proc = Process.Start(new ProcessStartInfo(command, args)
            {
                RedirectStandardOutput = true,
                UseShellExecute        = false,
                CreateNoWindow         = true
            });
            return proc?.StandardOutput.ReadToEnd() ?? string.Empty;
        }
        catch { return string.Empty; }
    }

    private static IReadOnlyList<InterfaceEntry> GetNetworkInterfaces()
    {
        var result = new List<InterfaceEntry>();
        try
        {
            int idx = 1;
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback
                         && n.OperationalStatus    == OperationalStatus.Up))
            {
                byte[] macBytes = ni.GetPhysicalAddress().GetAddressBytes();
                string mac = macBytes.Length > 0
                    ? string.Join(":", macBytes.Select(b => b.ToString("X2")))
                    : "N/A";

                string label = $"[{idx:D8}] {ni.Description}";

                foreach (UnicastIPAddressInformation ua in ni.GetIPProperties().UnicastAddresses)
                    result.Add(new InterfaceEntry(label, ua.Address.ToString(), mac));

                idx++;
            }
        }
        catch { /* best effort */ }
        return result;
    }
}
