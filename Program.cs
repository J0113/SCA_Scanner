// =============================================================================
//  Wazuh SCA Policy Scanner — C# Implementation
//  Usage:  ./SCAScanner <path/to/policy.yaml>
//          ./SCAScanner -h | --help
// =============================================================================

using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using SCAScanner;

// ── Helper Functions ──────────────────────────────────────────────────────

static SCAPolicy LoadPolicy(string path)
{
    string yaml = File.ReadAllText(path);
    IDeserializer deserializer = new DeserializerBuilder()
        .WithNamingConvention(UnderscoredNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();
    return deserializer.Deserialize<SCAPolicy>(yaml);
}

static string GetPlatform() =>
    OperatingSystem.IsWindows() ? "Windows" :
    OperatingSystem.IsMacOS()   ? "macOS"   : "Linux";

// ── Requirements check (silent) ──────────────────────────────────────────────

static bool RequirementsMet(SCAPolicy policy)
{
    if (policy.Requirements is null) return true;
    Check reqCheck = new()
    {
        Id        = 0,
        Title     = policy.Requirements.Title,
        Condition = policy.Requirements.Condition,
        Rules     = policy.Requirements.Rules
    };
    return RuleChecker.EvaluateCheck(reqCheck, policy.Variables).Status == CheckStatus.Passed;
}

// ── Directory Scan ────────────────────────────────────────────────────────────

static int ScanDirectory(string dirPath, IReporter reporter)
{
    List<string> files = Directory.GetFiles(dirPath, "*.yml")
        .Concat(Directory.GetFiles(dirPath, "*.yaml"))
        .OrderBy(f => f)
        .ToList();

    if (files.Count == 0)
    {
        reporter.PrintNoPolicesFound(dirPath);
        return 1;
    }

    reporter.PrintDiscoveryHeader(dirPath, files.Count);

    // ── Check requirements for each file ──────────────────────────────────────
    List<string> applicable = new();
    List<string> skipped = new();

    foreach (string file in files)
    {
        string fileName = Path.GetFileName(file);
        SCAPolicy policy;
        try { policy = LoadPolicy(file); }
        catch
        {
            reporter.PrintRequirementCheckLine(fileName, false, "parse error — skipped");
            skipped.Add(file);
            continue;
        }

        if (RequirementsMet(policy))
        {
            string note = policy.Requirements is null ? "no requirements" : "requirements met";
            reporter.PrintRequirementCheckLine(fileName, true, note);
            applicable.Add(file);
        }
        else
        {
            reporter.PrintRequirementCheckLine(fileName, false, "requirements not met — skipped");
            skipped.Add(file);
        }
    }

    if (applicable.Count == 0)
    {
        reporter.PrintError("No applicable policies found for this system.");
        return 1;
    }

    reporter.PrintApplicablePoliciesLine(applicable.Count);

    // ── Run each applicable policy ────────────────────────────────────────────
    int overallFailed = 0;
    for (int i = 0; i < applicable.Count; i++)
    {
        reporter.PrintPolicyExecutionHeader(i + 1, applicable.Count, Path.GetFileName(applicable[i]));
        int result = ScanCommand(applicable[i], reporter);
        if (result != 0) overallFailed++;
    }

    reporter.PrintDirectoryScanComplete(applicable.Count, overallFailed);

    return overallFailed > 0 ? 1 : 0;
}

// ── Scan Command ─────────────────────────────────────────────────────────

static int ScanCommand(string policyPath, IReporter reporter)
{
    if (!File.Exists(policyPath))
    {
        reporter.PrintError($"policy file not found → {policyPath}");
        return 1;
    }

    SCAPolicy policy;
    try
    {
        policy = LoadPolicy(policyPath);
    }
    catch (Exception ex)
    {
        reporter.PrintError($"parsing policy YAML: {ex.Message}");
        return 1;
    }

    reporter.PrintPolicyHeader(policy, GetPlatform());

    // ── Requirements ─────────────────────────────────────────────────────────────

    if (policy.Requirements is not null)
    {
        Check reqCheck = new()
        {
            Id          = 0,
            Title       = policy.Requirements.Title,
            Description = policy.Requirements.Description,
            Condition   = policy.Requirements.Condition,
            Rules       = policy.Requirements.Rules
        };

        CheckResult reqResult = RuleChecker.EvaluateCheck(reqCheck, policy.Variables);
        reporter.PrintRequirementsSection(reqCheck, policy.Variables, reqResult);

        if (reqResult.Status != CheckStatus.Passed)
            return 1;
    }

    // ── Run checks ────────────────────────────────────────────────────────────────

    int totalPassed = 0, totalFailed = 0, totalInvalid = 0;
    List<ScanCheckResult> checkResults = new();

    foreach (Check check in policy.Checks)
    {
        reporter.PrintCheckHeader(check);

        // ── Parse & explain rules before execution ──────────────────────────────
        List<ParsedRule> parsedRules = check.Rules
            .Select(rule => RuleParser.Parse(rule, policy.Variables))
            .ToList();

        reporter.PrintRuleExplanations(parsedRules, check, policy.Variables);

        // ── Execute ──────────────────────────────────────────────────────────────
        CheckResult result = RuleChecker.EvaluateCheck(check, policy.Variables);
        reporter.PrintRuleResults(result.RuleResults);
        reporter.PrintCheckResult(check, result, totalPassed, totalFailed);

        checkResults.Add(new ScanCheckResult
        {
            Id = check.Id,
            Title = check.Title,
            Status = result.Status,
            Reason = result.Reason
        });

        if (result.Status == CheckStatus.Passed)
            totalPassed++;
        else if (result.Status == CheckStatus.Failed)
            totalFailed++;
        else if (result.Status == CheckStatus.Invalid)
            totalInvalid++;
    }

    // ── Summary ───────────────────────────────────────────────────────────────────

    reporter.PrintScanSummary(totalPassed, totalFailed, totalInvalid, checkResults);

    return totalFailed > 0 ? 1 : 0;
}

// ── Main Entry Point ─────────────────────────────────────────────────────────

OutputLevel outputLevel = OutputLevel.Standard;
string? logFile = null;
string? csvFile = null;
string? target  = null;

for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "-h":
        case "--help":
            new ConsoleReporter().PrintHelp();
            return 0;
        case "--display-details":
            outputLevel = OutputLevel.Detailed;
            break;
        case "--no-details":
            outputLevel = OutputLevel.Compact;
            break;
        case "-l":
        case "--log":
            if (i + 1 < args.Length)
                logFile = args[++i];
            else
            {
                Console.Error.WriteLine("Error: -l/--log requires a file path argument.");
                return 1;
            }
            break;
        case "--csv":
            if (i + 1 < args.Length)
                csvFile = args[++i];
            else
            {
                Console.Error.WriteLine("Error: --csv requires a file path argument.");
                return 1;
            }
            break;
        default:
            if (target is null)
                target = args[i];
            else
            {
                Console.Error.WriteLine($"Error: unexpected argument '{args[i]}'.");
                return 1;
            }
            break;
    }
}

if (target is null)
{
    new ConsoleReporter().PrintHelp();
    return 0;
}

ConsoleReporter consoleReporter = new(outputLevel);
List<IReporter> reporters = [consoleReporter];
if (logFile is not null) reporters.Add(new FileReporter(logFile));
if (csvFile is not null) reporters.Add(new CsvReporter(csvFile));
IReporter reporter = reporters.Count > 1
    ? new CompositeReporter([.. reporters])
    : consoleReporter;

try
{
    if (Directory.Exists(target))
        return ScanDirectory(target, reporter);

    return ScanCommand(target, reporter);
}
finally
{
    if (reporter is IDisposable d) d.Dispose();
}
