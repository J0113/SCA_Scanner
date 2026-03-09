// =============================================================================
//  Wazuh SCA Policy Scanner — C# Implementation
//  Usage:  ./SCAScanner scan [path/to/policy.yaml]
//          ./SCAScanner validate [path/to/policy.yaml]
//          ./SCAScanner check "f:filename"
//          ./SCAScanner -h | --help
// =============================================================================

using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using SCAScanner;

// ── Helpers ──────────────────────────────────────────────────────────────────

static SCAPolicy LoadPolicy(string path)
{
    var yaml = File.ReadAllText(path);
    var deserializer = new DeserializerBuilder()
        .WithNamingConvention(UnderscoredNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();
    return deserializer.Deserialize<SCAPolicy>(yaml);
}

static void Write(string text, ConsoleColor color = ConsoleColor.Gray)
{
    Console.ForegroundColor = color;
    Console.Write(text);
    Console.ResetColor();
}

static void WriteLine(string text = "", ConsoleColor color = ConsoleColor.Gray)
{
    Console.ForegroundColor = color;
    Console.WriteLine(text);
    Console.ResetColor();
}

static void WritePass(string t)   => Write(t, ConsoleColor.Green);
static void WriteFail(string t)   => Write(t, ConsoleColor.Red);
static void WriteLabel(string t)  => Write(t, ConsoleColor.DarkCyan);
static void WriteGray(string t)   => Write(t, ConsoleColor.DarkGray);

static string Platform() =>
    OperatingSystem.IsWindows() ? "Windows" :
    OperatingSystem.IsMacOS()   ? "macOS"   : "Linux";

static void PrintBanner()
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("╔═════════════════════════════════════════════╗");
    Console.WriteLine("║          Wazuh SCA Policy Scanner           ║");
    Console.WriteLine("╚═════════════════════════════════════════════╝");
    Console.ResetColor();
    Console.WriteLine();
}

static void PrintHelp()
{
    PrintBanner();
    WriteLine("USAGE:", ConsoleColor.White);
    Console.WriteLine("  SCAScanner scan [path/to/policy.yaml]     Run all checks from a policy file");
    Console.WriteLine("  SCAScanner validate [path/to/policy.yaml] Show which checks are invalid");
    Console.WriteLine("  SCAScanner check \"f:filename\"             Check a specific file");
    Console.WriteLine("  SCAScanner -h, --help                      Show this help message");
    Console.WriteLine();
    WriteLine("EXAMPLES:", ConsoleColor.White);
    Console.WriteLine("  SCAScanner scan Policies/sample_policy.yaml");
    Console.WriteLine("  SCAScanner validate Policies/sample_policy.yaml");
    Console.WriteLine("  SCAScanner check \"f:/etc/passwd\"");
    Console.WriteLine();
}

// ── Validate Command ─────────────────────────────────────────────────────────

static int ValidateCommand(string policyPath)
{
    if (!File.Exists(policyPath))
    {
        WriteFail($"Error: policy file not found → {policyPath}\n");
        return 1;
    }

    SCAPolicy policy;
    try
    {
        policy = LoadPolicy(policyPath);
    }
    catch (Exception ex)
    {
        WriteFail($"Error parsing policy YAML: {ex.Message}\n");
        return 1;
    }

    PrintBanner();
    Console.ForegroundColor = ConsoleColor.White;
    Console.WriteLine($"  Policy   : {policy.Policy.Name}");
    Console.WriteLine($"  ID       : {policy.Policy.Id}");
    Console.WriteLine($"  Checks   : {policy.Checks.Count}");
    Console.ResetColor();
    Console.WriteLine();

    int totalValid = 0, totalInvalid = 0;
    var invalidChecks = new List<(int Id, string Title, string Error)>();

    // Validate requirements rules if present
    if (policy.Requirements is not null)
    {
        foreach (var rule in policy.Requirements.Rules)
        {
            try
            {
                RuleParser.Parse(rule, policy.Variables);
            }
            catch (Exception ex)
            {
                invalidChecks.Add((0, "Requirements", $"Invalid rule: {rule}\n            Error: {ex.Message}"));
                totalInvalid++;
            }
        }
        if (policy.Requirements.Rules.Count > 0 && totalInvalid == 0)
            totalValid += policy.Requirements.Rules.Count;
    }

    // Validate all check rules
    foreach (var check in policy.Checks)
    {
        bool hasError = false;
        foreach (var rule in check.Rules)
        {
            try
            {
                RuleParser.Parse(rule, policy.Variables);
            }
            catch (Exception ex)
            {
                if (!hasError)
                {
                    invalidChecks.Add((check.Id, check.Title, $"Invalid rule: {rule}\n            Error: {ex.Message}"));
                    hasError = true;
                }
                totalInvalid++;
            }
        }
        if (!hasError)
            totalValid += check.Rules.Count;
    }

    Console.WriteLine(new string('═', 68));
    WriteLine("  VALIDATION RESULTS", ConsoleColor.White);
    Console.WriteLine(new string('═', 68));

    if (invalidChecks.Count == 0)
    {
        WritePass($"  ✓ All {totalValid} rules are valid and can be parsed\n");
        return 0;
    }

    WriteFail($"  ✗ {invalidChecks.Count} check(s) have invalid rules:\n");
    foreach (var (id, title, error) in invalidChecks)
    {
        if (id == 0)
            Write($"    [REQS] ", ConsoleColor.DarkGray);
        else
            Write($"    [{id,-4}] ", ConsoleColor.DarkGray);
        WriteFail($"{title}\n");
        WriteGray($"            {error}\n");
    }
    Console.WriteLine($"  Valid rules   : {totalValid}");
    Console.WriteLine($"  Invalid rules : {totalInvalid}");
    Console.WriteLine();

    return 1;
}

// ── Check Command ────────────────────────────────────────────────────────────

static int CheckCommand(string checkSpec)
{
    // Parse the check spec (e.g., "f:filename" or "d:dirname")
    PrintBanner();
    
    if (!checkSpec.Contains(':'))
    {
        WriteFail("Error: invalid check specification format\n");
        WriteFail("Expected format: \"f:filename\" or \"d:dirname\"\n");
        return 1;
    }

    var parts = checkSpec.Split(':', 2);
    var type = parts[0];
    var target = parts[1];

    WriteLine("CHECK RESULT", ConsoleColor.White);
    Console.WriteLine();
    
    Write("  Type   : ", ConsoleColor.DarkGray);
    Console.WriteLine(type == "f" ? "File" : type == "d" ? "Directory" : "Unknown");
    Write("  Target : ", ConsoleColor.DarkGray);
    Console.WriteLine(target);
    Console.WriteLine();

    // Validate that the target exists
    bool exists = false;
    if (type == "f")
        exists = File.Exists(target);
    else if (type == "d")
        exists = Directory.Exists(target);

    if (exists)
    {
        WritePass("  ✓ Target found and is accessible\n");
        return 0;
    }
    else
    {
        WriteFail($"  ✗ Target not found\n");
        return 1;
    }
}

// ── Scan Command (Default) ───────────────────────────────────────────────────

static int ScanCommand(string policyPath)
{
    if (!File.Exists(policyPath))
    {
        WriteFail($"Error: policy file not found → {policyPath}\n");
        return 1;
    }

    SCAPolicy policy;
    try
    {
        policy = LoadPolicy(policyPath);
    }
    catch (Exception ex)
    {
        WriteFail($"Error parsing policy YAML: {ex.Message}\n");
        return 1;
    }

    PrintBanner();

    // ── Policy header ─────────────────────────────────────────────────────────────

    Console.ForegroundColor = ConsoleColor.White;
    Console.WriteLine($"  Policy   : {policy.Policy.Name}");
    Console.WriteLine($"  ID       : {policy.Policy.Id}");
    Console.WriteLine($"  Platform : {Platform()}");
    Console.WriteLine($"  Checks   : {policy.Checks.Count}");
    Console.ResetColor();

    if (!string.IsNullOrWhiteSpace(policy.Policy.Description))
        WriteLine($"  Desc     : {policy.Policy.Description}", ConsoleColor.DarkGray);

    Console.WriteLine();

    // ── Requirements ─────────────────────────────────────────────────────────────

    if (policy.Requirements is not null)
    {
        WriteLine("══ Requirements " + new string('═', 52), ConsoleColor.Cyan);
        Console.WriteLine($"  {policy.Requirements.Title}");
        if (!string.IsNullOrWhiteSpace(policy.Requirements.Description))
            WriteLine($"  {policy.Requirements.Description}", ConsoleColor.DarkGray);

        var reqCheck = new Check
        {
            Id          = 0,
            Title       = policy.Requirements.Title,
            Description = policy.Requirements.Description,
            Condition   = policy.Requirements.Condition,
            Rules       = policy.Requirements.Rules
        };

        // Explain requirement rules before executing
        WriteLabel("  ┌─ What requirements will be checked:\n");
        var parsedReqRules = policy.Requirements.Rules
            .Select(r => RuleParser.Parse(r, policy.Variables))
            .ToList();
        for (int i = 0; i < parsedReqRules.Count; i++)
        {
            WriteLabel($"  │  [{i + 1}] ");
            Console.WriteLine(RuleParser.Explain(parsedReqRules[i]));
            WriteGray($"  │       raw  : {policy.Requirements.Rules[i]}\n");
        }
        WriteLabel("  └─\n");

        var reqResult = RuleChecker.EvaluateCheck(reqCheck, policy.Variables);

        // Always show per-rule results so failures are self-explanatory
        WriteLabel("  ┌─ Requirement results:\n");
        for (int i = 0; i < reqResult.RuleResults.Count; i++)
        {
            var rr = reqResult.RuleResults[i];
            WriteLabel($"  │  [{i + 1}] ");
            if (rr.Passed) WritePass("PASS"); else WriteFail("FAIL");
            Console.WriteLine($"  {rr.Detail}");
        }
        WriteLabel("  └─\n\n");

        if (!reqResult.Passed)
        {
            WriteFail($"  ✗ Requirements NOT met — policy scan aborted.\n");
            WriteFail($"    {reqResult.Reason}\n");
            return 1;
        }
        WritePass("  ✓ Requirements met — proceeding with checks.\n");
        Console.WriteLine();
    }

    // ── Run checks ────────────────────────────────────────────────────────────────

    int totalPassed = 0, totalFailed = 0;
    var checkResults = new List<(int Id, string Title, bool Passed, string Reason)>();

    foreach (var check in policy.Checks)
    {
        Console.WriteLine(new string('─', 68));

        // Check title
        Write($"  [#{check.Id,-4}] ", ConsoleColor.DarkGray);
        WriteLine(check.Title, ConsoleColor.Yellow);

        if (!string.IsNullOrWhiteSpace(check.Description))
            WriteLine($"           Description : {check.Description}", ConsoleColor.Gray);
        if (!string.IsNullOrWhiteSpace(check.Rationale))
            WriteLine($"           Rationale   : {check.Rationale}", ConsoleColor.DarkGray);
        if (!string.IsNullOrWhiteSpace(check.Remediation))
            WriteLine($"           Remediation : {check.Remediation}", ConsoleColor.DarkYellow);

        WriteLine($"           Condition   : {check.Condition.ToUpper()} rules must pass", ConsoleColor.DarkGray);
        Console.WriteLine();

        // ── Parse & explain rules before execution ──────────────────────────────
        var parsedRules = check.Rules
            .Select(r => RuleParser.Parse(r, policy.Variables))
            .ToList();

        WriteLabel("  ┌─ What this check validates:\n");
        for (int i = 0; i < parsedRules.Count; i++)
        {
            WriteLabel($"  │  [{i + 1}] ");
            Console.WriteLine(RuleParser.Explain(parsedRules[i]));
            WriteGray($"  │       raw  : {check.Rules[i]}\n");
            if (policy.Variables is not null)
            {
                // Show expanded form when variables were substituted
                var expanded = check.Rules[i];
                bool hasVar  = false;
                foreach (var (k, v) in policy.Variables)
                    if (expanded.Contains(k)) { expanded = expanded.Replace(k, v); hasVar = true; }
                if (hasVar)
                    WriteGray($"  │       exp  : {expanded}\n");
            }
        }
        WriteLabel("  └─\n\n");

        // ── Execute ──────────────────────────────────────────────────────────────
        WriteLabel("  ┌─ Executing:\n");
        var result = RuleChecker.EvaluateCheck(check, policy.Variables);

        for (int i = 0; i < result.RuleResults.Count; i++)
        {
            var rr   = result.RuleResults[i];
            WriteLabel($"  │  [{i + 1}] ");
            if (rr.Passed) WritePass("PASS"); else WriteFail("FAIL");
            Console.WriteLine($"  {rr.Detail}");
        }

        Console.Write("  └─ ");
        if (result.Passed)
        {
            WritePass($"✓ PASSED");
            Console.WriteLine($"  ({result.Reason})");
            totalPassed++;
            checkResults.Add((check.Id, check.Title, true, result.Reason));
        }
        else
        {
            WriteFail($"✗ FAILED");
            Console.WriteLine($"  ({result.Reason})");
            totalFailed++;
            checkResults.Add((check.Id, check.Title, false, result.Reason));
        }

        Console.WriteLine();
    }

    // ── Summary ───────────────────────────────────────────────────────────────────

    Console.WriteLine(new string('═', 68));
    WriteLine("  SCAN SUMMARY", ConsoleColor.White);
    Console.WriteLine(new string('═', 68));

    int total = totalPassed + totalFailed;
    int score = total > 0 ? (int)Math.Round(totalPassed * 100.0 / total) : 0;

    WritePass($"  Passed  : {totalPassed}\n");
    WriteFail($"  Failed  : {totalFailed}\n");
    Console.WriteLine($"  Total   : {total}");
    Console.Write("  Score   : ");

    Console.ForegroundColor = score >= 75 ? ConsoleColor.Green
                            : score >= 50 ? ConsoleColor.Yellow
                            :               ConsoleColor.Red;
    Console.WriteLine($"{score}%");
    Console.ResetColor();
    Console.WriteLine();

    // ── Check Status Summary ──────────────────────────────────────────────────────

    WriteLine("  CHECK STATUS:", ConsoleColor.White);
    foreach (var (id, title, passed, reason) in checkResults)
    {
        Write($"    [{id,-4}] ", ConsoleColor.DarkGray);
        if (passed)
            WritePass("✓ PASS");
        else
            WriteFail("✗ FAIL");
        Console.WriteLine($"  {title}");
    }
    Console.WriteLine();

    return totalFailed > 0 ? 1 : 0;
}

// ── Main Entry Point ─────────────────────────────────────────────────────────

if (args.Length == 0 || args[0] == "-h" || args[0] == "--help")
{
    PrintHelp();
    return 0;
}

string command = args[0].ToLower();

if (command == "scan")
    return ScanCommand(args.Length > 1 ? args[1] : "Policies/sample_policy.yaml");
else if (command == "validate")
    return ValidateCommand(args.Length > 1 ? args[1] : "Policies/sample_policy.yaml");
else if (command == "check")
{
    if (args.Length > 1)
        return CheckCommand(args[1]);
    else
    {
        WriteFail("Error: check command requires a check specification\n");
        return 1;
    }
}
else
{
    WriteFail($"Error: unknown command '{command}'\n");
    PrintHelp();
    return 1;
}