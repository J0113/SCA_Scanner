namespace SCAScanner;

using System.Net;
using System.Runtime.InteropServices;
using System.Text;

/// <summary>
/// Writes scan results as a CSV file. One row per check result.
/// All IReporter methods are no-ops except PrintPolicyHeader, PrintCheckResult, and Dispose.
/// </summary>
public sealed class CsvReporter : IReporter, IDisposable
{
    private static readonly string[] Headers =
    [
        "Computer_Name", "Operating_System", "Standard", "Version",
        "Last_Scan_Date", "Description", "Fix_Text", "Rule", "Rule_ID", "Status"
    ];

    private readonly string _filePath;
    private readonly string _computerName;
    private readonly string _operatingSystem;
    private readonly string _scanDate;
    private string _standard = string.Empty;
    private string _version  = string.Empty;
    private readonly List<string[]> _rows = new();

    public CsvReporter(string filePath)
    {
        _filePath = filePath;

        _computerName = TryGetFqdn();
        _operatingSystem = RuntimeInformation.OSDescription;
        _scanDate = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
    }

    public void PrintPolicyHeader(SCAPolicy policy, string platform)
    {
        _standard = policy.Policy.Name;
        _version  = policy.Policy.Id;
    }

    public void PrintCheckResult(Check check, CheckResult result, int totalPassed, int totalFailed)
    {
        _rows.Add(
        [
            _computerName,
            _operatingSystem,
            _standard,
            _version,
            _scanDate,
            check.Description,
            check.Remediation,
            check.Title,
            check.Id.ToString(),
            result.Status.ToString()
        ]);
    }

    public void Dispose()
    {
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(",", Headers.Select(Escape)));
        foreach (var row in _rows)
            sb.AppendLine(string.Join(",", row.Select(Escape)));
        File.WriteAllText(_filePath, sb.ToString(), Encoding.UTF8);
    }

    /// <summary>RFC 4180 CSV escaping: wrap in quotes if value contains comma, quote, or newline.</summary>
    private static string Escape(string value)
    {
        if (value.Contains(',') || value.Contains('"') || value.Contains('\n') || value.Contains('\r'))
            return $"\"{value.Replace("\"", "\"\"")}\"";
        return value;
    }

    private static string TryGetFqdn()
    {
        try { return Dns.GetHostEntry("").HostName; }
        catch { return Environment.MachineName; }
    }

    // ── No-op IReporter methods ───────────────────────────────────────────────

    public void PrintBanner() { }
    public void PrintHelp() { }
    public void PrintRequirementsSection(Check requirementsCheck, PolicyVariables? variables, CheckResult requirementsResult) { }
    public void PrintCheckHeader(Check check) { }
    public void PrintRuleExplanations(List<ParsedRule> parsedRules, Check check, PolicyVariables? variables) { }
    public void PrintRuleResults(IReadOnlyList<RuleResult> ruleResults) { }
    public void PrintScanSummary(int passed, int failed, int invalid, List<ScanCheckResult> checkResults) { }
    public void PrintDiscoveryHeader(string directoryPath, int foundCount) { }
    public void PrintRequirementCheckLine(string fileName, bool met, string? note) { }
    public void PrintApplicablePoliciesLine(int applicableCount) { }
    public void PrintPolicyExecutionHeader(int index, int total, string policyFileName) { }
    public void PrintDirectoryScanComplete(int totalPolicies, int failedPolicies) { }
    public void PrintError(string message) { }
    public void PrintNoPolicesFound(string directoryPath) { }
}
