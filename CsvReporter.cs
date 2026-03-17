namespace SCAScanner;

using System.Net;
using System.Runtime.InteropServices;
using System.Text;

/// <summary>
/// Writes scan results as a CSV file. One row per check result.
/// Implements only <see cref="IPolicyReporter"/> and <see cref="ICheckReporter"/> —
/// all other output is irrelevant for CSV export.
/// </summary>
public sealed class CsvReporter : IPolicyReporter, ICheckReporter, IDisposable
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

        _computerName    = TryGetFqdn();
        _operatingSystem = RuntimeInformation.OSDescription;
        _scanDate        = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
    }

    // ── IPolicyReporter ───────────────────────────────────────────────────

    public void PrintBanner() { }
    public void PrintHelp()   { }

    public void PrintPolicyHeader(SCAPolicy policy, string platform)
    {
        _standard = policy.Policy.Name;
        _version  = policy.Policy.Id;
    }

    public void PrintRequirementsSection(Check requirementsCheck, PolicyVariables? variables, CheckResult requirementsResult) { }

    // ── ICheckReporter ────────────────────────────────────────────────────

    public void PrintCheckHeader(Check check) { }
    public void PrintRuleExplanations(List<ParsedRule> parsedRules, Check check, PolicyVariables? variables) { }
    public void PrintRuleResults(IReadOnlyList<RuleResult> ruleResults) { }

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

    // ── IDisposable ───────────────────────────────────────────────────────

    public void Dispose()
    {
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(",", Headers.Select(Escape)));
        foreach (var row in _rows)
            sb.AppendLine(string.Join(",", row.Select(Escape)));
        try
        {
            File.WriteAllText(_filePath, sb.ToString(), Encoding.UTF8);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"CsvReporter: failed to write '{_filePath}': {ex.Message}");
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

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
        catch (Exception) { return Environment.MachineName; }
    }
}
