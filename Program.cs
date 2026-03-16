// =============================================================================
//  Wazuh SCA Policy Scanner — C# Implementation
//  Usage:  ./SCAScanner <path/to/policy.yaml>
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
    Console.WriteLine("  SCAScanner <path/to/policy.yaml>   Run all checks from a policy file");
    Console.WriteLine("  SCAScanner <path/to/dir>           Scan all .yml/.yaml policies in a directory,");
    Console.WriteLine("                                     skipping those whose requirements don't apply");
    Console.WriteLine("  SCAScanner -h, --help              Show this help message");
    Console.WriteLine();
    WriteLine("EXAMPLES:", ConsoleColor.White);
    Console.WriteLine("  SCAScanner Policies/sample_policy.yaml");
    Console.WriteLine("  SCAScanner Policies/");
    Console.WriteLine();
}

// ── Requirements check (silent) ──────────────────────────────────────────────

static bool RequirementsMet(SCAPolicy policy)
{
    if (policy.Requirements is null) return true;
    var reqCheck = new Check
    {
        Id        = 0,
        Title     = policy.Requirements.Title,
        Condition = policy.Requirements.Condition,
        Rules     = policy.Requirements.Rules
    };
    return RuleChecker.EvaluateCheck(reqCheck, policy.Variables).Passed;
}

// ── Directory Scan ────────────────────────────────────────────────────────────

static int ScanDirectory(string dirPath)
{
    var files = Directory.GetFiles(dirPath, "*.yml")
        .Concat(Directory.GetFiles(dirPath, "*.yaml"))
        .OrderBy(f => f)
        .ToList();

    PrintBanner();

    if (files.Count == 0)
    {
        WriteFail($"  No .yml / .yaml files found in {dirPath}\n");
        return 1;
    }

    WriteLine("  POLICY DISCOVERY", ConsoleColor.White);
    Console.WriteLine($"  Directory : {Path.GetFullPath(dirPath)}");
    Console.WriteLine($"  Found     : {files.Count} policy file(s)");
    Console.WriteLine();

    // ── Check requirements for each file ──────────────────────────────────────
    var applicable = new List<string>();
    var skipped    = new List<string>();

    WriteLine("  Checking requirements...", ConsoleColor.DarkGray);
    foreach (var file in files)
    {
        var name = Path.GetFileName(file);
        SCAPolicy policy;
        try { policy = LoadPolicy(file); }
        catch
        {
            Write($"    ! {name,-40}", ConsoleColor.DarkYellow);
            WriteLine("  [parse error — skipped]", ConsoleColor.DarkYellow);
            skipped.Add(file);
            continue;
        }

        if (RequirementsMet(policy))
        {
            Write($"    ✓ {name,-40}", ConsoleColor.Green);
            string note = policy.Requirements is null ? "no requirements" : "requirements met";
            WriteLine($"  [{note}]", ConsoleColor.DarkGray);
            applicable.Add(file);
        }
        else
        {
            Write($"    ✗ {name,-40}", ConsoleColor.DarkGray);
            WriteLine("  [requirements not met — skipped]", ConsoleColor.DarkGray);
            skipped.Add(file);
        }
    }

    Console.WriteLine();

    if (applicable.Count == 0)
    {
        WriteFail("  No applicable policies found for this system.\n");
        return 1;
    }

    WriteLine($"  Running {applicable.Count} applicable policy file(s)...", ConsoleColor.White);
    Console.WriteLine();

    // ── Run each applicable policy ────────────────────────────────────────────
    int overallFailed = 0;
    for (int i = 0; i < applicable.Count; i++)
    {
        WriteLine($"{'═', -3} [{i + 1}/{applicable.Count}] {Path.GetFileName(applicable[i])} " +
                  new string('═', Math.Max(0, 52 - Path.GetFileName(applicable[i]).Length)),
                  ConsoleColor.Cyan);
        Console.WriteLine();
        int result = ScanCommand(applicable[i]);
        if (result != 0) overallFailed++;
        Console.WriteLine();
    }

    return overallFailed > 0 ? 1 : 0;
}

// ── Scan Command ─────────────────────────────────────────────────────────────

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

string target = args[0];

if (Directory.Exists(target))
    return ScanDirectory(target);

return ScanCommand(target);