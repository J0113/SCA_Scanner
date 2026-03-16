using System.Diagnostics;
using System.Text.RegularExpressions;

namespace SCAScanner;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// <summary>Result of evaluating a single rule string from a check's rules list.</summary>
public sealed record RuleResult(bool Passed, string Detail);

/// <summary>Result of evaluating an entire check (all its rules + condition).</summary>
public sealed record CheckResult(
    bool                    Passed,
    string                  Reason,
    IReadOnlyList<RuleResult> RuleResults);

// ---------------------------------------------------------------------------
// Checker
// ---------------------------------------------------------------------------

public static class RuleChecker
{
    // =========================================================================
    // Check evaluation  (applies condition: all / any / none)
    // =========================================================================

    public static CheckResult EvaluateCheck(Check check, PolicyVariables? variables)
    {
        List<RuleResult> results = check.Rules
            .Select(r => EvaluateRule(RuleParser.Parse(r, variables)))
            .ToList();

        int passCount = results.Count(r => r.Passed);

        bool passed = check.Condition.ToLowerInvariant() switch
        {
            "all"  => results.All(r => r.Passed),
            "any"  => results.Any(r => r.Passed),
            "none" => results.All(r => !r.Passed),
            _      => false
        };

        string reason = $"Condition '{check.Condition.ToUpper()}': {passCount}/{results.Count} rules passed";
        return new CheckResult(passed, reason, results);
    }

    // =========================================================================
    // Single rule evaluation (respects overall negation)
    // =========================================================================

    public static RuleResult EvaluateRule(ParsedRule rule)
    {
        (bool innerPassed, string detail) = rule.Type switch
        {
            RuleType.File      => CheckFile(rule),
            RuleType.Directory => CheckDirectory(rule),
            RuleType.Process   => CheckProcess(rule),
            RuleType.Command   => CheckCommand(rule),
            RuleType.Registry  => CheckRegistry(rule),
            _                  => (false, "Unknown rule type")
        };

        bool finalPassed = rule.Negated ? !innerPassed : innerPassed;
        string finalDetail = rule.Negated ? $"[NEGATED] {detail}" : detail;
        return new RuleResult(finalPassed, finalDetail);
    }

    // =========================================================================
    // Rule type handlers
    // =========================================================================

    // ── File ─────────────────────────────────────────────────────────────────
    private static (bool, string) CheckFile(ParsedRule rule)
    {
        if (!File.Exists(rule.Target))
            return (false, $"File not found: {rule.Target}");

        if (!rule.HasContentCheck)
        {
            FileInfo info = new(rule.Target);
            int lineCount = File.ReadAllLines(rule.Target).Length;
            return (true, $"File exists: {rule.Target}  ({FormatBytes(info.Length)}, {lineCount} lines)");
        }

        try
        {
            string content = File.ReadAllText(rule.Target);
            return EvaluateContent(content, rule.ContentConditions, label: $"'{rule.Target}'");
        }
        catch (Exception ex)
        {
            return (false, $"Cannot read '{rule.Target}': {ex.Message}");
        }
    }

    // ── Directory ────────────────────────────────────────────────────────────
    private static (bool, string) CheckDirectory(ParsedRule rule)
    {
        if (!Directory.Exists(rule.Target))
            return (false, $"Directory not found: {rule.Target}");

        if (!rule.HasContentCheck)
        {
            int count = Directory.GetFiles(rule.Target).Length;
            return (true, $"Directory exists: {rule.Target}  ({count} files)");
        }

        try
        {
            foreach (string file in Directory.EnumerateFiles(rule.Target))
            {
                string content = File.ReadAllText(file);
                (bool matched, string detail) = EvaluateContent(content, rule.ContentConditions, label: Path.GetFileName(file));
                if (matched) return (true, $"Match in {Path.GetFileName(file)}: {detail}");
            }
            return (false, $"No file in '{rule.Target}' matched the conditions");
        }
        catch (Exception ex)
        {
            return (false, $"Error reading directory '{rule.Target}': {ex.Message}");
        }
    }

    // ── Process ──────────────────────────────────────────────────────────────
    private static (bool, string) CheckProcess(ParsedRule rule)
    {
        Process[] procs = Process.GetProcessesByName(rule.Target);
        bool running = procs.Length > 0;

        if (running)
        {
            string pids = string.Join(", ", procs.Select(p => p.Id));
            return (true, $"Process '{rule.Target}' is running  (PID: {pids})");
        }
        return (false, $"Process '{rule.Target}' is not running  (0 instances found)");
    }

    // ── Command ──────────────────────────────────────────────────────────────
    private static (bool, string) CheckCommand(ParsedRule rule)
    {
        try
        {
            string shell, args;
            if (OperatingSystem.IsWindows())
            {
                shell = "cmd.exe";
                args  = $"/c {rule.Target}";
            }
            else
            {
                shell = "/bin/sh";
                args  = $"-c \"{rule.Target.Replace("\"", "\\\"")}\"";
            }

            ProcessStartInfo psi = new(shell, args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false
            };

            using Process proc = Process.Start(psi)!;
            // Read stdout and stderr concurrently to avoid deadlock when
            // either buffer fills, then combine them (many commands — like dscl —
            // write diagnostic output to stderr rather than stdout).
            Task<string> stdoutTask = proc.StandardOutput.ReadToEndAsync();
            Task<string> stderrTask  = proc.StandardError.ReadToEndAsync();
            Task.WaitAll([stdoutTask, stderrTask], millisecondsTimeout: 10_000);
            proc.WaitForExit(5_000);
            string output = stdoutTask.Result + stderrTask.Result;

            if (!rule.HasContentCheck)
            {
                bool ok      = proc.ExitCode == 0;
                string value = Truncate(output.Trim().ReplaceLineEndings(" "), 80);
                return (ok, $"Exit code {proc.ExitCode}  → \"{value}\"");
            }

            return EvaluateContent(output, rule.ContentConditions, label: $"`{rule.Target}`");
        }
        catch (Exception ex)
        {
            return (false, $"Failed to run command '{rule.Target}': {ex.Message}");
        }
    }

    // ── Registry ─────────────────────────────────────────────────────────────
    private static (bool, string) CheckRegistry(ParsedRule rule)
    {
        if (!OperatingSystem.IsWindows())
            return (false, "Registry checks are only supported on Windows — skipped on this platform");

        try
        {
            string keyPath = rule.Target;

            int firstBackslash = keyPath.IndexOf('\\');
            if (firstBackslash < 0)
                return (false, $"Invalid registry key path: {keyPath}");

            string hiveName = keyPath[..firstBackslash].ToUpperInvariant();
            string subKey   = keyPath[(firstBackslash + 1)..];

            // Support both full names and common short aliases
            Microsoft.Win32.RegistryKey? hive = hiveName switch
            {
                "HKEY_LOCAL_MACHINE"  or "HKLM" => Microsoft.Win32.Registry.LocalMachine,
                "HKEY_CURRENT_USER"   or "HKCU" => Microsoft.Win32.Registry.CurrentUser,
                "HKEY_CLASSES_ROOT"   or "HKCR" => Microsoft.Win32.Registry.ClassesRoot,
                "HKEY_USERS"          or "HKU"  => Microsoft.Win32.Registry.Users,
                "HKEY_CURRENT_CONFIG" or "HKCC" => Microsoft.Win32.Registry.CurrentConfig,
                _ => null
            };

            if (hive is null)
                return (false, $"Unknown registry hive: '{hiveName}' — valid hives: HKLM, HKCU, HKCR, HKU, HKCC");

            using Microsoft.Win32.RegistryKey? key = hive.OpenSubKey(subKey);
            if (key is null)
                return (false, $"Registry key not found: {keyPath}");

            // ── Key existence only ────────────────────────────────────────
            if (!rule.HasContentCheck)
            {
                int valueCount = key.ValueCount;
                return (true, $"Registry key exists: {keyPath}  ({valueCount} values)");
            }

            // ── 3-part: KEY -> ValueName -> [DataPattern] ─────────────────
            if (rule.RegistryValueName is not null)
            {
                object? value = key.GetValue(rule.RegistryValueName);
                if (value is null)
                    return (false, $"Registry value '{rule.RegistryValueName}' not found in '{keyPath}'");

                string valueStr = value.ToString() ?? string.Empty;

                // Value exists, no data pattern required
                if (rule.ContentConditions.Count == 0)
                    return (true, $"Registry value '{rule.RegistryValueName}' = \"{valueStr}\" in '{keyPath}'");

                // Match data pattern against the value string
                return EvaluateContent(valueStr, rule.ContentConditions,
                    label: $"'{rule.RegistryValueName}' in {keyPath}");
            }

            // ── Fallback: match content against all name=value pairs ──────
            System.Text.StringBuilder allValues = new();
            foreach (string name in key.GetValueNames())
                allValues.AppendLine($"{name}={key.GetValue(name)}");

            return EvaluateContent(allValues.ToString(), rule.ContentConditions, label: keyPath);
        }
        catch (Exception ex)
        {
            return (false, $"Registry error: {ex.Message}");
        }
    }

    // =========================================================================
    // Content evaluation  (shared by File, Directory, Command, Registry)
    // =========================================================================

    /// <summary>
    /// Evaluates one or more content conditions against <paramref name="content"/>.
    ///
    /// Single condition  → line-by-line: pass if ANY line satisfies the condition
    ///                     (or, for negated, if NO line matches the pattern).
    ///
    /// Multiple (&&) conditions → line-by-line: pass if ANY line simultaneously
    ///                            satisfies ALL conditions (Wazuh semantics).
    /// </summary>
    private static (bool matched, string detail) EvaluateContent(
        string content,
        List<ContentCondition> conditions,
        string label)
    {
        if (conditions.Count == 0)
            return (true, "No content conditions");

        if (conditions.Count == 1)
            return EvaluateSingleCondition(content, conditions[0], label);

        // Multi-condition (&&): look for a line that satisfies ALL conditions
        string[] lines = SplitLines(content);
        foreach (string line in lines)
        {
            if (conditions.All(c => LineMatchesCondition(line, c)))
                return (true, $"Matched line in {label}: \"{Truncate(line.Trim(), 80)}\"");
        }

        // Show the first non-empty line as context for the failure
        string sample = lines.FirstOrDefault(l => l.Trim().Length > 0)?.Trim() ?? "(empty)";
        return (false, $"No single line in {label} satisfies all {conditions.Count} AND-conditions  (first line: \"{Truncate(sample, 60)}\")");
    }

    private static (bool, string) EvaluateSingleCondition(
        string content, ContentCondition cond, string label)
    {
        if (cond.Operator == ContentOperator.Numeric)
            return EvaluateNumeric(content, cond, label);

        string[] lines = SplitLines(content);

        if (!cond.Negated)
        {
            // Pass if ANY line matches the pattern
            foreach (string line in lines)
            {
                if (MatchesPattern(line, cond.Pattern, cond.Operator))
                    return (true, $"Matched line in {label}: \"{Truncate(line.Trim(), 80)}\"");
            }
            // Show the first line as context so the user knows what was actually there
            string sample = lines.FirstOrDefault(l => l.Trim().Length > 0)?.Trim() ?? "(empty)";
            return (false, $"Pattern `{cond.Pattern}` not found in {label}  (first line: \"{Truncate(sample, 60)}\")");
        }
        else
        {
            // Pass if NO line matches the pattern
            foreach (string line in lines)
            {
                if (MatchesPattern(line, cond.Pattern, cond.Operator))
                    return (false, $"Forbidden pattern found in {label}: \"{Truncate(line.Trim(), 80)}\"");
            }
            // Show first line to confirm what IS in the content
            string sample = lines.FirstOrDefault(l => l.Trim().Length > 0)?.Trim() ?? "(empty)";
            return (true, $"Pattern `{cond.Pattern}` absent from {label}  (actual first line: \"{Truncate(sample, 60)}\")");
        }
    }

    private static (bool, string) EvaluateNumeric(
        string content, ContentCondition cond, string label)
    {
        Regex regex;
        try   { regex = new Regex(cond.Pattern, RegexOptions.Multiline); }
        catch { return (false, $"Invalid numeric regex pattern: `{cond.Pattern}`"); }

        Match match = regex.Match(content);
        if (!match.Success || match.Groups.Count < 2)
        {
            string sample = Truncate(content.Trim().ReplaceLineEndings(" "), 60);
            return (false, $"Pattern `{cond.Pattern}` found no capture group in {label}  (actual: \"{sample}\")");
        }

        if (!double.TryParse(match.Groups[1].Value, out double value))
            return (false, $"Captured '{match.Groups[1].Value}' in {label} is not numeric");

        bool met = cond.NumericOp switch
        {
            NumericComparison.LessThan           => value < cond.NumericValue,
            NumericComparison.LessThanOrEqual    => value <= cond.NumericValue,
            NumericComparison.Equal              => value == cond.NumericValue,
            NumericComparison.NotEqual           => value != cond.NumericValue,
            NumericComparison.GreaterThanOrEqual => value >= cond.NumericValue,
            NumericComparison.GreaterThan        => value > cond.NumericValue,
            _                                    => false
        };

        string sym = cond.NumericOp switch
        {
            NumericComparison.LessThan           => "<",
            NumericComparison.LessThanOrEqual    => "<=",
            NumericComparison.Equal              => "==",
            NumericComparison.NotEqual           => "!=",
            NumericComparison.GreaterThanOrEqual => ">=",
            NumericComparison.GreaterThan        => ">",
            _                                    => "?"
        };

        bool finalPassed = cond.Negated ? !met : met;
        return (finalPassed, $"Captured value = {value}  ({value} {sym} {cond.NumericValue} → {(finalPassed ? "PASS" : "FAIL")})  from {label}");
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private static bool MatchesPattern(string line, string pattern, ContentOperator op) =>
        op switch
        {
            ContentOperator.Literal => line.Contains(pattern, StringComparison.Ordinal),
            ContentOperator.Regex   => Regex.IsMatch(line, pattern),
            _                       => false
        };

    private static bool LineMatchesCondition(string line, ContentCondition cond)
    {
        bool raw = MatchesPattern(line, cond.Pattern, cond.Operator);
        return cond.Negated ? !raw : raw;
    }

    private static string[] SplitLines(string text) =>
        text.Split(['\n', '\r'], StringSplitOptions.RemoveEmptyEntries);

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";

    private static string FormatBytes(long bytes) =>
        bytes switch
        {
            < 1024             => $"{bytes} B",
            < 1024 * 1024      => $"{bytes / 1024.0:F1} KB",
            _                  => $"{bytes / (1024.0 * 1024):F1} MB"
        };
}
