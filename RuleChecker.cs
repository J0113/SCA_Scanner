using System.Diagnostics;
using System.Text.RegularExpressions;

namespace SCAScanner;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// <summary>Result of evaluating a single rule string from a check's rules list.</summary>
public sealed record RuleResult(bool Passed, bool Invalid, string Detail);

/// <summary>Result of evaluating an entire check (all its rules + condition).</summary>
public sealed record CheckResult(
    CheckStatus             Status,
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

        bool hasInvalid = results.Any(r => r.Invalid);
        bool hasValidPass = results.Where(r => !r.Invalid).Any(r => r.Passed);
        bool hasValidFail = results.Where(r => !r.Invalid).Any(r => !r.Passed);
        int passCount = results.Count(r => r.Passed && !r.Invalid);
        int validCount = results.Count(r => !r.Invalid);

        // Evaluate based on condition type and whether there are invalid rules
        string condType = check.Condition.ToLowerInvariant();
        CheckStatus status;
        string reason;

        if (condType == "any")
        {
            // ANY: requires at least one rule to pass
            // If there's a valid pass, result is PASS (even with invalids)
            // If all valid rules fail (none pass), result is FAIL (proven outcome)
            // If all rules are invalid, result is INVALID (can't execute any)
            if (hasValidPass)
            {
                status = CheckStatus.Passed;
                reason = $"Condition 'ANY': at least one rule passed";
            }
            else if (validCount == 0)
            {
                // All rules are invalid → can't execute any
                status = CheckStatus.Invalid;
                reason = "Check invalid: all rules cannot be executed";
            }
            else if (!hasValidPass && validCount > 0)
            {
                // All valid rules fail (none pass) → proven to fail
                status = CheckStatus.Failed;
                reason = $"Condition 'ANY': {passCount}/{validCount} rules passed";
            }
            else
            {
                status = CheckStatus.Failed;
                reason = $"Condition 'ANY': {passCount}/{validCount} rules passed";
            }
        }
        else if (condType == "all")
        {
            // ALL: requires all rules to pass
            // If there are any invalid rules, we can't confirm all pass → INVALID (unless proven to fail)
            // But a single definite failure overrides invalid (proves it will fail)
            bool allValidPass = !hasValidFail && validCount > 0;

            if (hasInvalid)
            {
                if (validCount == 0)
                {
                    // All rules are invalid → can't execute any
                    status = CheckStatus.Invalid;
                    reason = "Check invalid: all rules cannot be executed";
                }
                else if (hasValidFail)
                {
                    // Have both invalid and valid fails → proven to fail
                    status = CheckStatus.Failed;
                    reason = $"Condition 'ALL': {passCount}/{validCount} rules passed";
                }
                else if (allValidPass)
                {
                    // All valid rules pass but some are invalid → can't confirm all pass
                    status = CheckStatus.Invalid;
                    reason = "Check invalid: one or more rules cannot be executed";
                }
                else
                {
                    // All valid rules fail → definitely FAIL
                    status = CheckStatus.Failed;
                    reason = $"Condition 'ALL': {passCount}/{validCount} rules passed";
                }
            }
            else
            {
                // No invalid rules, use standard ALL logic
                bool allPassed = results.All(r => r.Passed);
                status = allPassed ? CheckStatus.Passed : CheckStatus.Failed;
                reason = $"Condition 'ALL': {passCount}/{validCount} rules passed";
            }
        }
        else if (condType == "none")
        {
            // NONE: requires all rules to fail (none pass)
            // If we know at least one rule passed (without being invalid), result is FAIL
            // If all rules are invalid, result is INVALID
            // If there are invalid rules but no passes, result is INVALID
            if (hasValidPass)
            {
                status = CheckStatus.Failed;
                reason = $"Condition 'NONE': {passCount}/{validCount} rules passed";
            }
            else if (hasInvalid)
            {
                // If all rules are invalid, can't execute any
                if (validCount == 0)
                {
                    status = CheckStatus.Invalid;
                    reason = "Check invalid: all rules cannot be executed";
                }
                else
                {
                    // Some rules are invalid but valid ones all failed
                    status = CheckStatus.Invalid;
                    reason = "Check invalid: one or more rules cannot be executed";
                }
            }
            else
            {
                bool nonePassed = results.All(r => !r.Passed);
                status = nonePassed ? CheckStatus.Passed : CheckStatus.Failed;
                reason = $"Condition 'NONE': {passCount}/{validCount} rules passed";
            }
        }
        else
        {
            status = CheckStatus.Failed;
            reason = $"Unknown condition: {check.Condition}";
        }

        return new CheckResult(status, reason, results);
    }

    // =========================================================================
    // Single rule evaluation (respects overall negation)
    // =========================================================================

    public static RuleResult EvaluateRule(ParsedRule rule)
    {
        // If the rule definition itself is invalid, return invalid status
        if (rule.Invalid)
        {
            return new RuleResult(false, true, $"Invalid rule: {rule.InvalidReason ?? "malformed"}");
        }

        RuleCheckResult checkResult = rule.Type switch
        {
            RuleType.File      => CheckFile(rule),
            RuleType.Directory => CheckDirectory(rule),
            RuleType.Process   => CheckProcess(rule),
            RuleType.Command   => CheckCommand(rule),
            RuleType.Registry  => CheckRegistry(rule),
            _                  => new RuleCheckResult { Status = CheckStatus.Failed, Detail = "Unknown rule type" }
        };

        // If the rule is invalid, propagate that status and don't apply negation
        if (checkResult.Status == CheckStatus.Invalid)
            return new RuleResult(false, true, checkResult.Detail);

        bool innerPassed = checkResult.Status == CheckStatus.Passed;
        bool finalPassed = rule.Negated ? !innerPassed : innerPassed;
        string finalDetail = rule.Negated ? $"[NEGATED] {checkResult.Detail}" : checkResult.Detail;
        return new RuleResult(finalPassed, false, finalDetail);
    }

    // =========================================================================
    // Rule type handlers
    // =========================================================================

    // ── File ─────────────────────────────────────────────────────────────────
    private static RuleCheckResult CheckFile(ParsedRule rule)
    {
        // Handle comma-separated file paths (OR logic: stop at first existing)
        string[] files = rule.Target.Split(',');
        string? foundFile = null;

        foreach (string file in files)
        {
            string trimmedFile = file.Trim();
            if (File.Exists(trimmedFile))
            {
                foundFile = trimmedFile;
                break;
            }
        }

        if (foundFile is null)
        {
            // If the file doesn't exist and we need to check its content, that's invalid
            if (rule.HasContentCheck)
                return new RuleCheckResult { Status = CheckStatus.Invalid, Detail = $"Cannot check content: file not found at {rule.Target}" };
            // If the file doesn't exist and we just need to check existence, it fails
            return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"File not found: {rule.Target}" };
        }

        if (!rule.HasContentCheck)
        {
            FileInfo info = new(foundFile);
            int lineCount = File.ReadAllLines(foundFile).Length;
            return new RuleCheckResult { Status = CheckStatus.Passed, Detail = $"File exists: {foundFile}  ({FormatBytes(info.Length)}, {lineCount} lines)" };
        }

        try
        {
            string content = File.ReadAllText(foundFile);
            var (matched, detail) = EvaluateContent(content, rule.ContentConditions, label: $"'{foundFile}'");
            return new RuleCheckResult { Status = matched ? CheckStatus.Passed : CheckStatus.Failed, Detail = detail };
        }
        catch (Exception ex)
        {
            return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"Cannot read '{foundFile}': {ex.Message}" };
        }
    }

    // ── Directory ────────────────────────────────────────────────────────────
    private static RuleCheckResult CheckDirectory(ParsedRule rule)
    {
        // Handle comma-separated directory paths (OR logic: stop at first existing)
        string[] dirs = rule.Target.Split(',');
        string? foundDir = null;

        foreach (string dir in dirs)
        {
            string trimmedDir = dir.Trim();
            if (Directory.Exists(trimmedDir))
            {
                foundDir = trimmedDir;
                break;
            }
        }

        if (foundDir is null)
        {
            // If the directory doesn't exist and we need to check content, that's invalid
            if (rule.HasContentCheck)
                return new RuleCheckResult { Status = CheckStatus.Invalid, Detail = $"Cannot check content: directory not found at {rule.Target}" };
            // If the directory doesn't exist and we just need to check existence, it fails
            return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"Directory not found: {rule.Target}" };
        }

        if (!rule.HasContentCheck)
        {
            int count = Directory.GetFiles(foundDir).Length;
            return new RuleCheckResult { Status = CheckStatus.Passed, Detail = $"Directory exists: {foundDir}  ({count} files)" };
        }

        // For directory rules: patterns are filename matches, not content searches
        // - Literal operator = exact filename match
        // - Regex operator = regex pattern to match against filenames
        try
        {
            string[] allFiles = Directory.GetFiles(foundDir);

            foreach (var condition in rule.ContentConditions)
            {
                if (condition.Operator == ContentOperator.Literal)
                {
                    // Exact filename match
                    string? matchedFile = null;
                    if (condition.Negated)
                    {
                        // Check if any file doesn't have this exact name
                        matchedFile = allFiles.FirstOrDefault(f => Path.GetFileName(f) != condition.Pattern);
                        if (matchedFile is not null)
                            return new RuleCheckResult { Status = CheckStatus.Passed, Detail = $"File not named '{condition.Pattern}' found: {Path.GetFileName(matchedFile)}" };
                        return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"All files in '{foundDir}' are named '{condition.Pattern}'" };
                    }
                    else
                    {
                        // Check if file exists with exact name
                        matchedFile = allFiles.FirstOrDefault(f => Path.GetFileName(f) == condition.Pattern);
                        if (matchedFile is not null)
                            return new RuleCheckResult { Status = CheckStatus.Passed, Detail = $"File found: {Path.GetFileName(matchedFile)}" };
                        return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"File '{condition.Pattern}' not found in '{foundDir}'" };
                    }
                }
                else if (condition.Operator == ContentOperator.Regex)
                {
                    // Regex pattern match against filenames
                    string? matchedFile = null;
                    try
                    {
                        var regex = new System.Text.RegularExpressions.Regex(condition.Pattern);
                        if (condition.Negated)
                        {
                            // Check if any file doesn't match the pattern
                            matchedFile = allFiles.FirstOrDefault(f => !regex.IsMatch(Path.GetFileName(f)));
                            if (matchedFile is not null)
                                return new RuleCheckResult { Status = CheckStatus.Passed, Detail = $"File not matching pattern found: {Path.GetFileName(matchedFile)}" };
                            return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"All files in '{foundDir}' match the pattern" };
                        }
                        else
                        {
                            // Check if any file matches the pattern
                            matchedFile = allFiles.FirstOrDefault(f => regex.IsMatch(Path.GetFileName(f)));
                            if (matchedFile is not null)
                                return new RuleCheckResult { Status = CheckStatus.Passed, Detail = $"File matching pattern found: {Path.GetFileName(matchedFile)}" };
                            return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"No file in '{foundDir}' matches the pattern" };
                        }
                    }
                    catch (System.Text.RegularExpressions.RegexParseException ex)
                    {
                        return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"Invalid regex pattern '{condition.Pattern}': {ex.Message}" };
                    }
                }
            }
            return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"No matching conditions" };
        }
        catch (Exception ex)
        {
            return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"Error checking directory '{foundDir}': {ex.Message}" };
        }
    }

    // ── Process ──────────────────────────────────────────────────────────────
    private static RuleCheckResult CheckProcess(ParsedRule rule)
    {
        // Support both literal process names and regex patterns (p:r:PATTERN)
        if (rule.Target.StartsWith("r:", StringComparison.Ordinal))
        {
            // Regex pattern matching
            string pattern = rule.Target[2..];
            try
            {
                var regex = new System.Text.RegularExpressions.Regex(pattern);
                Process[] allProcs = Process.GetProcesses();
                var matchedProcs = allProcs.Where(p => regex.IsMatch(p.ProcessName)).ToArray();

                if (matchedProcs.Length > 0)
                {
                    string pids = string.Join(", ", matchedProcs.Select(p => p.Id));
                    string names = string.Join(", ", matchedProcs.Select(p => p.ProcessName).Distinct());
                    return new RuleCheckResult { Status = CheckStatus.Passed, Detail = $"Process matching pattern '{pattern}' is running: {names}  (PID: {pids})" };
                }
                return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"No process matching pattern '{pattern}' found" };
            }
            catch (System.Text.RegularExpressions.RegexParseException ex)
            {
                return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"Invalid regex pattern '{pattern}': {ex.Message}" };
            }
        }
        else
        {
            // Literal process name matching
            Process[] procs = Process.GetProcessesByName(rule.Target);
            bool running = procs.Length > 0;

            if (running)
            {
                string pids = string.Join(", ", procs.Select(p => p.Id));
                return new RuleCheckResult { Status = CheckStatus.Passed, Detail = $"Process '{rule.Target}' is running  (PID: {pids})" };
            }
            return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"Process '{rule.Target}' is not running  (0 instances found)" };
        }
    }

    // ── Command ──────────────────────────────────────────────────────────────
    private static RuleCheckResult CheckCommand(ParsedRule rule)
    {
        try
        {
            string shell, args;
            if (OperatingSystem.IsWindows())
            {
                // Use PowerShell if command starts with "powershell"
                if (rule.Target.StartsWith("powershell ", StringComparison.OrdinalIgnoreCase))
                {
                    shell = "powershell.exe";
                    args  = rule.Target[11..];  // Pass remaining args as-is (user already specified -Command, etc.)
                }
                else
                {
                    shell = "cmd.exe";
                    args  = $"/c {rule.Target}";
                }
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
                return new RuleCheckResult { Status = ok ? CheckStatus.Passed : CheckStatus.Failed, Detail = $"Exit code {proc.ExitCode}  → \"{value}\"" };
            }

            // For content checks: non-zero exit code is only INVALID if:
            // Exit code is 127 (command not found)
            // Other exit codes (1, 2, etc.) mean the command ran but failed → evaluate output or fail
            if (proc.ExitCode == 127)
            {
                return new RuleCheckResult { Status = CheckStatus.Invalid, Detail = $"Command execution failed with exit code {proc.ExitCode}" };
            }

            var (matched, detail) = EvaluateContent(output, rule.ContentConditions, label: $"`{rule.Target}`");
            return new RuleCheckResult { Status = matched ? CheckStatus.Passed : CheckStatus.Failed, Detail = detail };
        }
        catch (Exception ex)
        {
            return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"Failed to run command '{rule.Target}': {ex.Message}" };
        }
    }

    // ── Registry ─────────────────────────────────────────────────────────────
    private static RuleCheckResult CheckRegistry(ParsedRule rule)
    {
        if (!OperatingSystem.IsWindows())
            return new RuleCheckResult { Status = CheckStatus.Invalid, Detail = "Registry checks are only supported on Windows — skipped on this platform" };

        try
        {
            string keyPath = rule.Target;

            int firstBackslash = keyPath.IndexOf('\\');
            if (firstBackslash < 0)
                return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"Invalid registry key path: {keyPath}" };

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
                return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"Unknown registry hive: '{hiveName}' — valid hives: HKLM, HKCU, HKCR, HKU, HKCC" };

            using Microsoft.Win32.RegistryKey? key = hive.OpenSubKey(subKey);
            if (key is null)
            {
                // If key doesn't exist and we need to check content patterns, that's invalid
                // (2-part rules checking value existence should still FAIL)
                if (rule.ContentConditions.Count > 0)
                    return new RuleCheckResult { Status = CheckStatus.Invalid, Detail = $"Cannot check content: registry key not found at {keyPath}" };
                // If key doesn't exist and we just need to check existence, it fails
                return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"Registry key not found: {keyPath}" };
            }

            // ── Key existence only ────────────────────────────────────────
            if (!rule.HasContentCheck)
            {
                int valueCount = key.ValueCount;
                return new RuleCheckResult { Status = CheckStatus.Passed, Detail = $"Registry key exists: {keyPath}  ({valueCount} values)" };
            }

            // ── 3-part: KEY -> ValueName -> [DataPattern] ─────────────────
            if (rule.RegistryValueName is not null)
            {
                object? value = key.GetValue(rule.RegistryValueName);
                if (value is null)
                {
                    // If value doesn't exist and we need to check its data, that's invalid
                    if (rule.ContentConditions.Count > 0)
                        return new RuleCheckResult { Status = CheckStatus.Invalid, Detail = $"Cannot check content: registry value '{rule.RegistryValueName}' not found in '{keyPath}'" };
                    // If value doesn't exist and we just need to check its existence, it fails
                    return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"Registry value '{rule.RegistryValueName}' not found in '{keyPath}'" };
                }

                string valueStr = value.ToString() ?? string.Empty;

                // Value exists, no data pattern required
                if (rule.ContentConditions.Count == 0)
                    return new RuleCheckResult { Status = CheckStatus.Passed, Detail = $"Registry value '{rule.RegistryValueName}' = \"{valueStr}\" in '{keyPath}'" };

                // Match data pattern against the value string
                var (matched, detail) = EvaluateContent(valueStr, rule.ContentConditions,
                    label: $"'{rule.RegistryValueName}' in {keyPath}");
                return new RuleCheckResult { Status = matched ? CheckStatus.Passed : CheckStatus.Failed, Detail = detail };
            }

            // ── Fallback: match content against all name=value pairs ──────
            System.Text.StringBuilder allValues = new();
            foreach (string name in key.GetValueNames())
                allValues.AppendLine($"{name}={key.GetValue(name)}");

            var (matched2, detail2) = EvaluateContent(allValues.ToString(), rule.ContentConditions, label: keyPath);
            return new RuleCheckResult { Status = matched2 ? CheckStatus.Passed : CheckStatus.Failed, Detail = detail2 };
        }
        catch (Exception ex)
        {
            return new RuleCheckResult { Status = CheckStatus.Failed, Detail = $"Registry error: {ex.Message}" };
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
