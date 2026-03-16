namespace SCAScanner;

/// <summary>
/// Console-based implementation of IReporter with colored output.
/// Encapsulates all console-specific formatting and color logic.
/// </summary>
public sealed class ConsoleReporter : IReporter
{
    // ─ Console helper methods ────────────────────────────────────────────

    private void Write(string text, ConsoleColor color = ConsoleColor.Gray)
    {
        Console.ForegroundColor = color;
        Console.Write(text);
        Console.ResetColor();
    }

    private void WriteLine(string text = "", ConsoleColor color = ConsoleColor.Gray)
    {
        Console.ForegroundColor = color;
        Console.WriteLine(text);
        Console.ResetColor();
    }

    private void WritePass(string text) => Write(text, ConsoleColor.Green);
    private void WriteFail(string text) => Write(text, ConsoleColor.Red);
    private void WriteLabel(string text) => Write(text, ConsoleColor.DarkCyan);
    private void WriteGray(string text) => Write(text, ConsoleColor.DarkGray);

    private static string Truncate(string text, int maxLength) =>
        text.Length <= maxLength ? text : text[..maxLength] + "…";

    // =========================================================================
    // UI Structure
    // =========================================================================

    public void PrintBanner()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("╔═════════════════════════════════════════════╗");
        Console.WriteLine("║          Wazuh SCA Policy Scanner           ║");
        Console.WriteLine("╚═════════════════════════════════════════════╝");
        Console.ResetColor();
        Console.WriteLine();
    }

    public void PrintHelp()
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

    // =========================================================================
    // Policy Execution Context
    // =========================================================================

    public void PrintPolicyHeader(SCAPolicy policy, string platform)
    {
        PrintBanner();

        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"  Policy   : {policy.Policy.Name}");
        Console.WriteLine($"  ID       : {policy.Policy.Id}");
        Console.WriteLine($"  Platform : {platform}");
        Console.WriteLine($"  Checks   : {policy.Checks.Count}");
        Console.ResetColor();

        if (!string.IsNullOrWhiteSpace(policy.Policy.Description))
            WriteLine($"  Desc     : {policy.Policy.Description}", ConsoleColor.DarkGray);

        Console.WriteLine();
    }

    public void PrintRequirementsSection(Check requirementsCheck, PolicyVariables? variables, CheckResult requirementsResult)
    {
        Requirements requirements = new()
        {
            Title = requirementsCheck.Title,
            Description = requirementsCheck.Description,
            Condition = requirementsCheck.Condition,
            Rules = requirementsCheck.Rules
        };

        WriteLine("══ Requirements " + new string('═', 52), ConsoleColor.Cyan);
        Console.WriteLine($"  {requirements.Title}");
        if (!string.IsNullOrWhiteSpace(requirements.Description))
            WriteLine($"  {requirements.Description}", ConsoleColor.DarkGray);

        // Explain requirement rules before executing
        WriteLabel("  ┌─ What requirements will be checked:\n");
        List<ParsedRule> parsedReqRules = requirements.Rules
            .Select(rule => RuleParser.Parse(rule, variables))
            .ToList();
        for (int i = 0; i < parsedReqRules.Count; i++)
        {
            WriteLabel($"  │  [{i + 1}] ");
            Console.WriteLine(RuleParser.Explain(parsedReqRules[i]));
            WriteGray($"  │       raw  : {requirements.Rules[i]}\n");
        }
        WriteLabel("  └─\n");

        // Show per-rule results
        WriteLabel("  ┌─ Requirement results:\n");
        for (int i = 0; i < requirementsResult.RuleResults.Count; i++)
        {
            RuleResult ruleResult = requirementsResult.RuleResults[i];
            WriteLabel($"  │  [{i + 1}] ");
            if (ruleResult.Passed) WritePass("PASS"); else WriteFail("FAIL");
            Console.WriteLine($"  {ruleResult.Detail}");
        }
        WriteLabel("  └─\n\n");

        if (!requirementsResult.Passed)
        {
            WriteFail($"  ✗ Requirements NOT met — policy scan aborted.\n");
            WriteFail($"    {requirementsResult.Reason}\n");
        }
        else
        {
            WritePass("  ✓ Requirements met — proceeding with checks.\n");
            Console.WriteLine();
        }
    }

    // =========================================================================
    // Check Execution
    // =========================================================================

    public void PrintCheckHeader(Check check)
    {
        Console.WriteLine(new string('─', 68));

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
    }

    public void PrintRuleExplanations(List<ParsedRule> parsedRules, Check check, PolicyVariables? variables)
    {
        WriteLabel("  ┌─ What this check validates:\n");
        for (int i = 0; i < parsedRules.Count; i++)
        {
            WriteLabel($"  │  [{i + 1}] ");
            Console.WriteLine(RuleParser.Explain(parsedRules[i]));
            WriteGray($"  │       raw  : {check.Rules[i]}\n");
            if (variables?.HasVariables == true)
            {
                string expanded = check.Rules[i];
                bool hasVar = false;
                foreach (var (key, value) in variables.Values)
                    if (expanded.Contains(key)) { expanded = expanded.Replace(key, value); hasVar = true; }
                if (hasVar)
                    WriteGray($"  │       exp  : {expanded}\n");
            }
        }
        WriteLabel("  └─\n\n");
    }

    public void PrintRuleResults(IReadOnlyList<RuleResult> ruleResults)
    {
        WriteLabel("  ┌─ Executing:\n");
        for (int i = 0; i < ruleResults.Count; i++)
        {
            RuleResult ruleResult = ruleResults[i];
            WriteLabel($"  │  [{i + 1}] ");
            if (ruleResult.Passed) WritePass("PASS"); else WriteFail("FAIL");
            Console.WriteLine($"  {ruleResult.Detail}");
        }
    }

    public void PrintCheckResult(Check check, CheckResult result, int totalPassed, int totalFailed)
    {
        Console.Write("  └─ ");
        if (result.Passed)
        {
            WritePass($"✓ PASSED");
            Console.WriteLine($"  ({result.Reason})");
        }
        else
        {
            WriteFail($"✗ FAILED");
            Console.WriteLine($"  ({result.Reason})");
        }

        Console.WriteLine();
    }

    // =========================================================================
    // Summary
    // =========================================================================

    public void PrintScanSummary(int passed, int failed, List<ScanCheckResult> checkResults)
    {
        Console.WriteLine(new string('═', 68));
        WriteLine("  SCAN SUMMARY", ConsoleColor.White);
        Console.WriteLine(new string('═', 68));

        int total = passed + failed;
        int score = total > 0 ? (int)Math.Round(passed * 100.0 / total) : 0;

        WritePass($"  Passed  : {passed}\n");
        WriteFail($"  Failed  : {failed}\n");
        Console.WriteLine($"  Total   : {total}");
        Console.Write("  Score   : ");

        Console.ForegroundColor = score >= 75 ? ConsoleColor.Green
                                : score >= 50 ? ConsoleColor.Yellow
                                :               ConsoleColor.Red;
        Console.WriteLine($"{score}%");
        Console.ResetColor();
        Console.WriteLine();

        WriteLine("  CHECK STATUS:", ConsoleColor.White);
        foreach (ScanCheckResult result in checkResults)
        {
            Write($"    [{result.Id,-4}] ", ConsoleColor.DarkGray);
            if (result.Passed)
                WritePass("✓ PASS");
            else
                WriteFail("✗ FAIL");
            Console.WriteLine($"  {result.Title}");
        }
        Console.WriteLine();
    }

    // =========================================================================
    // Directory Scanning
    // =========================================================================

    public void PrintDiscoveryHeader(string directoryPath, int foundCount)
    {
        PrintBanner();

        WriteLine("  POLICY DISCOVERY", ConsoleColor.White);
        Console.WriteLine($"  Directory : {Path.GetFullPath(directoryPath)}");
        Console.WriteLine($"  Found     : {foundCount} policy file(s)");
        Console.WriteLine();

        WriteLine("  Checking requirements...", ConsoleColor.DarkGray);
    }

    public void PrintRequirementCheckLine(string fileName, bool met, string? note)
    {
        if (met)
        {
            Write($"    ✓ {fileName,-40}", ConsoleColor.Green);
            WriteLine($"  [{note}]", ConsoleColor.DarkGray);
        }
        else
        {
            Write($"    ✗ {fileName,-40}", ConsoleColor.DarkGray);
            WriteLine($"  [{note}]", ConsoleColor.DarkGray);
        }
    }

    public void PrintApplicablePoliciesLine(int applicableCount)
    {
        Console.WriteLine();
        WriteLine($"  Running {applicableCount} applicable policy file(s)...", ConsoleColor.White);
        Console.WriteLine();
    }

    public void PrintPolicyExecutionHeader(int index, int total, string policyFileName)
    {
        WriteLine($"{'═', -3} [{index}/{total}] {policyFileName} " +
                  new string('═', Math.Max(0, 52 - policyFileName.Length)),
                  ConsoleColor.Cyan);
        Console.WriteLine();
    }

    public void PrintDirectoryScanComplete(int totalPolicies, int failedPolicies)
    {
        Console.WriteLine();
    }

    // =========================================================================
    // Error Messages
    // =========================================================================

    public void PrintError(string message)
    {
        WriteFail($"Error: {message}\n");
    }

    public void PrintNoPolicesFound(string directoryPath)
    {
        WriteFail($"  No .yml / .yaml files found in {directoryPath}\n");
    }
}
