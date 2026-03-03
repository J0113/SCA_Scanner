using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace SCA_Scanner;

public static class SCAFileRunner
{
    // ── Public entry point ────────────────────────────────────────────────────

    public static void RunFile(string yamlPath)
    {
        if (!File.Exists(yamlPath))
        {
            WriteColor($"File not found: {yamlPath}", ConsoleColor.Red);
            return;
        }

        ScaFile scaFile;
        try
        {
            scaFile = LoadYaml(yamlPath);
        }
        catch (Exception ex)
        {
            WriteColor($"Failed to parse YAML: {ex.Message}", ConsoleColor.Red);
            return;
        }

        PrintHeader(scaFile.Policy);

        if (scaFile.Requirements is not null && !EvaluateRequirements(scaFile.Requirements))
        {
            WriteColor("  Requirements not satisfied — this policy does not apply to this system.", ConsoleColor.Yellow);
            return;
        }

        var results = scaFile.Checks.Select(EvaluateCheck).ToList();

        PrintSummary(scaFile.Policy, results);
    }

    // ── YAML loading ──────────────────────────────────────────────────────────

    private static ScaFile LoadYaml(string path)
    {
        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();

        using var reader = new StreamReader(path);
        return deserializer.Deserialize<ScaFile>(reader)
               ?? throw new InvalidDataException("YAML produced a null result.");
    }

    // ── Header ────────────────────────────────────────────────────────────────

    private static void PrintHeader(PolicyMeta policy)
    {
        Console.WriteLine(new string('═', 76));
        Console.WriteLine($"  Policy : {policy.Id}");
        Console.WriteLine($"  Name   : {policy.Name}");
        Console.WriteLine(new string('═', 76));
        Console.WriteLine();
    }

    // ── Requirements ──────────────────────────────────────────────────────────

    private static bool EvaluateRequirements(RequirementsSection req)
    {
        Console.WriteLine($"  ┌─ Requirements: {req.Title}");

        var results = req.Rules.Select(rule => SafeEvaluate(rule)).ToList();

        bool passed = ApplyCondition(req.Condition, results.Select(r => r.Passed).ToList());

        foreach (var r in results)
            PrintRuleOutcome(r, indent: 4);

        Console.WriteLine($"  └─ Requirements {(passed ? "✓ met" : "✗ not met")}");
        Console.WriteLine();
        return passed;
    }

    // ── Check evaluation ──────────────────────────────────────────────────────

    private static CheckResult EvaluateCheck(ScaCheck check)
    {
        Console.WriteLine(new string('─', 76));
        Console.WriteLine($"  [{check.Id}] {check.Title}");
        Console.WriteLine($"  Condition : {check.Condition.ToUpper()}");
        Console.WriteLine();

        var ruleResults = check.Rules.Select(rule => SafeEvaluate(rule)).ToList();

        foreach (var r in ruleResults)
            PrintRuleOutcome(r, indent: 2);

        bool passed = ApplyCondition(check.Condition, ruleResults.Select(r => r.Passed).ToList());

        Console.Write($"\n  ► ");
        WriteColor(passed ? "✓  PASS" : "✗  FAIL", passed ? ConsoleColor.Green : ConsoleColor.Red);
        Console.WriteLine();

        return new CheckResult(check.Id, check.Title, check.Condition, ruleResults, passed);
    }

    // ── Condition logic ───────────────────────────────────────────────────────

    private static bool ApplyCondition(string condition, List<bool> results) =>
        condition.ToLowerInvariant() switch
        {
            "all" => results.All(r => r),
            "any" => results.Any(r => r),
            "none" => results.All(r => !r),
            _ => results.All(r => r)   // default to "all"
        };

    // ── Safe evaluation wrapper ───────────────────────────────────────────────

    private static RuleResult SafeEvaluate(string rule)
    {
        try
        {
            bool passed = RuleEvaluator.Evaluate(rule);
            return new RuleResult(rule, passed);
        }
        catch (Exception ex)
        {
            WriteColor($"  ⚠  Rule error: {ex.Message}", ConsoleColor.Yellow);
            return new RuleResult(rule, Passed: false, Error: ex.Message);
        }
    }

    // ── Summary ───────────────────────────────────────────────────────────────

    private static void PrintSummary(PolicyMeta policy, List<CheckResult> results)
    {
        int passed = results.Count(r => r.Passed);
        int failed = results.Count(r => !r.Passed);

        Console.WriteLine(new string('═', 76));
        Console.WriteLine($"  SUMMARY  ·  {policy.Name}");
        Console.WriteLine($"  Total: {results.Count}   Pass: {passed}   Fail: {failed}");
        Console.WriteLine(new string('─', 76));

        foreach (var r in results)
        {
            Console.Write($"  [{r.Id,5}]  ");
            WriteColor(r.Passed ? "✓ PASS" : "✗ FAIL", r.Passed ? ConsoleColor.Green : ConsoleColor.Red);

            // Truncate long titles for readability
            string title = r.Title.Length > 55 ? r.Title[..52] + "…" : r.Title;
            Console.WriteLine($"  {title}");
        }

        Console.WriteLine(new string('═', 76));

        // Score line
        double score = results.Count == 0 ? 0 : 100.0 * passed / results.Count;
        Console.Write($"\n  Score: ");
        WriteColor($"{score:F1}%", score >= 80 ? ConsoleColor.Green : score >= 50 ? ConsoleColor.Yellow : ConsoleColor.Red);
        Console.WriteLine($"  ({passed}/{results.Count} checks passed)\n");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static void PrintRuleOutcome(RuleResult r, int indent)
    {
        string pad = new(' ', indent);
        string icon = r.Passed ? "✓" : "✗";
        ConsoleColor color = r.Passed ? ConsoleColor.Green : ConsoleColor.Red;
        Console.Write($"{pad}");
        WriteColor($"{icon}", color);

        // Trim rule to first ' -> ' for a compact display
        int sep = r.Rule.IndexOf(" -> ", StringComparison.Ordinal);
        string shortRule = sep > 0 ? r.Rule[..sep].TrimStart('c', 'r', ':').Trim() : r.Rule;
        if (shortRule.Length > 65) shortRule = shortRule[..62] + "…";

        Console.WriteLine($"  {shortRule}");
    }

    private static void WriteColor(string text, ConsoleColor color)
    {
        Console.ForegroundColor = color;
        Console.Write(text);
        Console.ResetColor();
    }
}
