using System;
using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

// ─────────────────────────────────────────────────────────────────────────────
// SCA Rule Evaluator
// Supports:
//   c:COMMAND -> r:REGEX                          Command + regex match
//   c:COMMAND -> n:REGEX compare OP NUMBER        Command + numeric compare
//   r:HKEY\PATH                                   Registry key exists
//   r:HKEY\PATH -> ValueName                      Registry value exists
//   r:HKEY\PATH -> ValueName -> Expected          Registry value matches
//   (any annotation)  rule                        Strips annotations
//   not RULE                                      Negation
// ─────────────────────────────────────────────────────────────────────────────

namespace SCA_Scanner
{

    internal static class RuleEvaluator
    {
        // ── Public entry point ────────────────────────────────────────────────

        public static void Run(string rawRule)
        {
            Console.WriteLine(new string('─', 74));
            Console.WriteLine($"  Rule   : {rawRule}");
            Console.WriteLine();

            try
            {
                bool result = Evaluate(rawRule);
                Console.ForegroundColor = result ? ConsoleColor.Green : ConsoleColor.Red;
                Console.WriteLine($"  Result : {(result ? "✓  PASS" : "✗  FAIL")}");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"  Error  : {ex.Message}");
                Console.ResetColor();
                Console.WriteLine($"  Result : ⚠  ERROR");
            }

            Console.WriteLine();
        }

        // ── Rule dispatcher ───────────────────────────────────────────────────
        public static bool Evaluate(string rawRule)
        {
            string rule = rawRule.Trim();

            // Normalise \\ → \ (YAML single-quoted strings store \\ for a literal backslash)
            rule = rule.Replace(@"\\", @"\");

            rule = Regex.Replace(rule, @"^\([^)]*\)\s*", string.Empty).Trim();

            bool negate = Regex.IsMatch(rule, @"^not\s+", RegexOptions.IgnoreCase);
            if (negate)
                rule = Regex.Replace(rule, @"^not\s+", string.Empty, RegexOptions.IgnoreCase).Trim();

            bool result = rule[..2].ToLowerInvariant() switch
            {
                "c:" => EvaluateCommand(rule[2..]),
                "r:" => EvaluateRegistry(rule[2..]),
                _ => throw new NotSupportedException($"Unknown rule prefix: {rule[..2]}")
            };

            if (negate)
            {
                Console.WriteLine("          ↳ negated by 'not'");
                return !result;
            }

            return result;
        }


        // ── Command rules: c:COMMAND -> check ────────────────────────────────

        private static bool EvaluateCommand(string body)
        {
            // Split on the FIRST occurrence of ' -> '
            int sep = body.IndexOf(" -> ", StringComparison.Ordinal);
            if (sep < 0)
                throw new ArgumentException("Command rule is missing a ' -> ' check separator.");

            // Unescape \\ → \ (rule files often store escaped backslashes)
            string command = body[..sep].Trim().Replace(@"\\", @"\");
            string check = body[(sep + 4)..].Trim();

            DescribeCommandCheck(command, check);

            string output = Execute(command);

            // Trim and show output (condensed to first 3 lines for readability)
            string[] lines = output.TrimEnd().Split('\n');
            string preview = string.Join(" | ", lines[..Math.Min(3, lines.Length)]).Trim();
            Console.WriteLine($"  Output : {(preview.Length == 0 ? "(empty)" : preview)}");

            return ApplyOutputCheck(output, check);
        }

        private static void DescribeCommandCheck(string command, string check)
        {
            Console.WriteLine($"  Command: {command}");

            if (check.StartsWith("n:", StringComparison.OrdinalIgnoreCase))
            {
                var m = ParseNumericCheck(check);
                Console.WriteLine(m is not null
                    ? $"  Check  : Numeric – extract regex /{m.Pattern}/, assert value {m.Op} {m.Threshold}"
                    : $"  Check  : {check}  (parse failed)");
            }
            else if (check.StartsWith("r:", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine($"  Check  : Regex – output must match /{check[2..]}/");
            }
            else
            {
                Console.WriteLine($"  Check  : {check}");
            }
        }

        private static bool ApplyOutputCheck(string output, string check)
        {
            // ── Numeric check: n:REGEX compare OP NUMBER ──────────────────────
            if (check.StartsWith("n:", StringComparison.OrdinalIgnoreCase))
            {
                var parsed = ParseNumericCheck(check)
                    ?? throw new ArgumentException($"Cannot parse numeric check: {check}");

                var match = Regex.Match(output, parsed.Pattern, RegexOptions.Multiline);
                if (!match.Success)
                {
                    Console.WriteLine($"  ↳ Pattern /{parsed.Pattern}/ not found in output → false");
                    return false;
                }

                // Prefer first explicit capture group, fall back to whole match
                string captured = match.Groups.Count > 1 && match.Groups[1].Success
                    ? match.Groups[1].Value
                    : match.Value;

                if (!double.TryParse(captured, out double value))
                {
                    Console.WriteLine($"  ↳ Could not parse '{captured}' as a number → false");
                    return false;
                }

                bool pass = NumericCompare(value, parsed.Op, parsed.Threshold);
                Console.WriteLine($"  ↳ Extracted {value}  {parsed.Op}  {parsed.Threshold}  →  {pass}");
                return pass;
            }

            // ── Regex check: r:PATTERN ─────────────────────────────────────────
            if (check.StartsWith("r:", StringComparison.OrdinalIgnoreCase))
            {
                string pattern = check[2..];
                bool found = Regex.IsMatch(output, pattern,
                    RegexOptions.Multiline | RegexOptions.IgnoreCase);
                Console.WriteLine($"  ↳ Pattern /{pattern}/ matched  →  {found}");
                return found;
            }

            throw new NotSupportedException($"Unknown output check type: {check}");
        }

        // ── Registry rules: r:HIVE\PATH [-> value [-> expected]] ─────────────

        private static bool EvaluateRegistry(string body)
        {
            string[] parts = body.Split(new[] { " -> " }, StringSplitOptions.None);
            string keyPath = parts[0].Trim();
            string? valName = parts.Length > 1 ? parts[1].Trim() : null;
            string? expected = parts.Length > 2 ? parts[2].Trim() : null;

            var (hive, subKey) = ParseHive(keyPath);
            if (hive is null)
                throw new ArgumentException($"Unrecognised registry hive in: {keyPath}");

            // ── Key existence ─────────────────────────────────────────────────
            if (valName is null)
            {
                Console.WriteLine($"  Check  : Registry key exists");
                Console.WriteLine($"  Path   : {keyPath}");
                using var k = hive.OpenSubKey(subKey);
                bool exists = k is not null;
                Console.WriteLine($"  ↳ Key exists  →  {exists}");
                return exists;
            }

            // ── Value existence ───────────────────────────────────────────────
            if (expected is null)
            {
                Console.WriteLine($"  Check  : Registry value exists");
                Console.WriteLine($"  Path   : {keyPath}  →  {valName}");
                using var k = hive.OpenSubKey(subKey);
                if (k is null) { Console.WriteLine("  ↳ Key not found  →  false"); return false; }
                bool has = k.GetValue(valName) is not null;
                Console.WriteLine($"  ↳ Value '{valName}' present  →  {has}");
                return has;
            }

            // ── Value content match ───────────────────────────────────────────
            {
                Console.WriteLine($"  Check  : Registry value matches expected");
                Console.WriteLine($"  Path   : {keyPath}  →  {valName}  →  {expected}");
                using var k = hive.OpenSubKey(subKey);
                if (k is null) { Console.WriteLine("  ↳ Key not found  →  false"); return false; }
                object? raw = k.GetValue(valName);
                if (raw is null) { Console.WriteLine($"  ↳ Value '{valName}' not found  →  false"); return false; }

                string actual = raw.ToString()!;
                // Try exact match first, then regex pattern match
                bool match;
                if (expected.StartsWith("r:", StringComparison.OrdinalIgnoreCase))
                {
                    // Explicit regex — use as-is, no forced anchors
                    string pattern = expected[2..];
                    match = Regex.IsMatch(actual, pattern, RegexOptions.IgnoreCase);
                    Console.WriteLine($"  ↳ Actual '{actual}'  matches regex /{pattern}/  →  {match}");
                }
                else
                {
                    // Literal string — exact case-insensitive equality
                    match = actual.Equals(expected, StringComparison.OrdinalIgnoreCase);
                    Console.WriteLine($"  ↳ Actual '{actual}'  equals '{expected}'  →  {match}");
                }

                Console.WriteLine($"  ↳ Actual '{actual}'  matches '{expected}'  →  {match}");
                return match;
            }
        }

        // ── Process execution ─────────────────────────────────────────────────

        private static string Execute(string command)
        {
            ProcessStartInfo psi;

            if (command.StartsWith("powershell", StringComparison.OrdinalIgnoreCase))
            {
                // Strip the 'powershell' prefix and use encoded command to
                // avoid quoting hell with semicolons, pipes, and $env vars.
                string script = command["powershell".Length..].Trim();
                string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

                psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
            }
            else
            {
                psi = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {command}",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
            }

            using var proc = Process.Start(psi)
                ?? throw new InvalidOperationException("Failed to start process.");

            string stdout = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(30_000);
            return stdout;
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private record NumericCheckParts(string Pattern, string Op, double Threshold);

        private static NumericCheckParts? ParseNumericCheck(string check)
        {
            // n:PATTERN compare OP THRESHOLD
            var m = Regex.Match(check,
                @"^n:(.+?)\s+compare\s+([<>=!]{1,2})\s+(-?\d+(?:\.\d+)?)$",
                RegexOptions.IgnoreCase);

            return m.Success
                ? new NumericCheckParts(m.Groups[1].Value, m.Groups[2].Value,
                                        double.Parse(m.Groups[3].Value))
                : null;
        }

        private static bool NumericCompare(double value, string op, double threshold) => op switch
        {
            "<=" => value <= threshold,
            ">=" => value >= threshold,
            "<" => value < threshold,
            ">" => value > threshold,
            "==" or "=" => Math.Abs(value - threshold) < 1e-10,
            "!=" => Math.Abs(value - threshold) >= 1e-10,
            _ => throw new NotSupportedException($"Unknown comparison operator: '{op}'")
        };

        private static (RegistryKey? hive, string subKey) ParseHive(string path)
        {
            (string Prefix, RegistryKey Hive)[] map =
            [
                ("HKEY_LOCAL_MACHINE\\",  Registry.LocalMachine),
                ("HKLM\\",               Registry.LocalMachine),
                ("HKEY_CURRENT_USER\\",  Registry.CurrentUser),
                ("HKCU\\",               Registry.CurrentUser),
                ("HKEY_CLASSES_ROOT\\",  Registry.ClassesRoot),
                ("HKCR\\",               Registry.ClassesRoot),
                ("HKEY_USERS\\",         Registry.Users),
                ("HKU\\",                Registry.Users),
                ("HKEY_CURRENT_CONFIG\\",Registry.CurrentConfig),
                ("HKCC\\",               Registry.CurrentConfig),
            ];

            foreach (var (prefix, hive) in map)
                if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    return (hive, path[prefix.Length..]);

            return (null, string.Empty);
        }
    }
}
