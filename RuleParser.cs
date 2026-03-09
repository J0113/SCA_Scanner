using System.Text;

namespace SCAScanner;

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// <summary>The subject a rule operates on.</summary>
public enum RuleType
{
    File,       // f:
    Directory,  // d:
    Process,    // p:
    Command,    // c:
    Registry    // r:
}

/// <summary>How the content value is matched.</summary>
public enum ContentOperator
{
    Literal,    // plain string containment
    Regex,      // r: prefix
    Numeric     // n: prefix  + compare operator
}

public enum NumericComparison
{
    LessThan, LessThanOrEqual, Equal, NotEqual, GreaterThanOrEqual, GreaterThan
}

// ---------------------------------------------------------------------------
// A single content condition (the part after "->", one segment split by &&)
// ---------------------------------------------------------------------------
public sealed class ContentCondition
{
    /// <summary>True when prefixed with ! (pattern must NOT be found).</summary>
    public bool             Negated     { get; set; }
    public ContentOperator  Operator    { get; set; }
    public string           Pattern     { get; set; } = string.Empty;
    // Numeric only
    public NumericComparison? NumericOp  { get; set; }
    public double?          NumericValue { get; set; }
}

// ---------------------------------------------------------------------------
// A fully parsed rule string
// ---------------------------------------------------------------------------
public sealed class ParsedRule
{
    /// <summary>True when the rule is prefixed with "not " or "!".</summary>
    public bool                   Negated           { get; set; }
    public RuleType               Type              { get; set; }
    /// <summary>File path, process name, command string, or registry key path.</summary>
    public string                 Target            { get; set; } = string.Empty;
    public bool                   HasContentCheck   { get; set; }
    /// <summary>
    /// Registry only: the value name in the 3-part format
    /// r:KEY -> ValueName -> DataPattern
    /// </summary>
    public string?                RegistryValueName { get; set; }
    /// <summary>One or more conditions connected by && in the original rule string.</summary>
    public List<ContentCondition> ContentConditions { get; set; } = [];
    public string                 OriginalText      { get; set; } = string.Empty;
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------
public static class RuleParser
{
    private static readonly string[] AndSeparator = [" && "];
    private static readonly string[] ArrowSeparator = [" -> "];

    /// <summary>
    /// Parse a raw SCA rule string into a <see cref="ParsedRule"/>, expanding
    /// any $variable references beforehand.
    /// </summary>
    public static ParsedRule Parse(string raw, Dictionary<string, string>? variables = null)
    {
        var original = raw;

        // Expand $variables
        if (variables is not null)
            foreach (var (k, v) in variables)
                raw = raw.Replace(k, v);

        var rule = new ParsedRule { OriginalText = original };

        // ── Overall negation ─────────────────────────────────────────────
        // Wazuh supports both "not " prefix and leading "!" (for non-registry)
        if (raw.StartsWith("not ", StringComparison.OrdinalIgnoreCase))
        {
            rule.Negated = true;
            raw = raw[4..];
        }
        // "!" negation only when NOT followed by a content-operator prefix
        else if (raw.Length > 2 && raw[0] == '!' && raw[1] != 'r' && raw[1] != 'n')
        {
            rule.Negated = true;
            raw = raw[1..];
        }

        // ── Rule type prefix ──────────────────────────────────────────────
        if      (raw.StartsWith("f:")) { rule.Type = RuleType.File;      raw = raw[2..]; }
        else if (raw.StartsWith("d:")) { rule.Type = RuleType.Directory;  raw = raw[2..]; }
        else if (raw.StartsWith("p:")) { rule.Type = RuleType.Process;    raw = raw[2..]; }
        else if (raw.StartsWith("c:")) { rule.Type = RuleType.Command;    raw = raw[2..]; }
        else if (raw.StartsWith("r:")) { rule.Type = RuleType.Registry;   raw = raw[2..]; }
        else
        {
            throw new InvalidOperationException(
                $"Invalid rule format: '{original}'\n" +
                "Rules must start with a type prefix: f:, d:, p:, c:, or r:");
        }

        // ── Target vs content ─────────────────────────────────────────────
        if (rule.Type == RuleType.Registry)
        {
            // Registry uses a 3-part format:  KEY -> ValueName -> DataPattern
            // All three parts separated by " -> "; DataPattern is optional.
            var regParts = raw.Split(ArrowSeparator, 3, StringSplitOptions.None);
            rule.Target = regParts[0].Trim();
            if (regParts.Length >= 2)
            {
                rule.HasContentCheck    = true;
                rule.RegistryValueName  = regParts[1].Trim();
            }
            if (regParts.Length >= 3)
                rule.ContentConditions.Add(ParseContentCondition(regParts[2].Trim()));
        }
        else
        {
            // Split on the FIRST occurrence of " -> "
            var parts = raw.Split(ArrowSeparator, 2, StringSplitOptions.None);
            rule.Target = parts[0].Trim();
            if (parts.Length == 2)
            {
                rule.HasContentCheck = true;
                // Each segment separated by " && " is an independent condition
                foreach (var seg in parts[1].Split(AndSeparator, StringSplitOptions.None))
                    rule.ContentConditions.Add(ParseContentCondition(seg.Trim()));
            }
        }

        return rule;
    }

    // ── Content condition parser ──────────────────────────────────────────
    private static ContentCondition ParseContentCondition(string s)
    {
        var cond = new ContentCondition();

        if (s.StartsWith('!'))
        {
            cond.Negated = true;
            s = s[1..];
        }

        if (s.StartsWith("r:"))
        {
            cond.Operator = ContentOperator.Regex;
            cond.Pattern  = s[2..];
        }
        else if (s.StartsWith("n:"))
        {
            cond.Operator = ContentOperator.Numeric;
            ParseNumericCondition(cond, s[2..]);
        }
        else
        {
            cond.Operator = ContentOperator.Literal;
            cond.Pattern  = s;
        }

        return cond;
    }

    // Format: REGEX_WITH_(\d+) compare OPERATOR VALUE
    private static void ParseNumericCondition(ContentCondition cond, string s)
    {
        const string sep = " compare ";
        var idx = s.IndexOf(sep, StringComparison.Ordinal);

        if (idx < 0)
        {
            cond.Pattern = s;
            return;
        }

        cond.Pattern = s[..idx];
        var comparison = s[(idx + sep.Length)..].Trim().Split(' ', 2);

        cond.NumericOp = comparison[0] switch
        {
            "<"  => NumericComparison.LessThan,
            "<=" => NumericComparison.LessThanOrEqual,
            "==" => NumericComparison.Equal,
            "!=" => NumericComparison.NotEqual,
            ">=" => NumericComparison.GreaterThanOrEqual,
            ">"  => NumericComparison.GreaterThan,
            _    => NumericComparison.Equal
        };

        if (comparison.Length > 1 && double.TryParse(comparison[1], out var v))
            cond.NumericValue = v;
    }

    // =========================================================================
    // Human-readable explanation (called BEFORE execution to explain intent)
    // =========================================================================

    public static string Explain(ParsedRule rule)
    {
        var sb = new StringBuilder();
        var neg = rule.Negated ? "NOT " : string.Empty;

        if (!rule.HasContentCheck)
        {
            var verb = rule.Type switch
            {
                RuleType.File      => $"{neg}File '{rule.Target}' must exist",
                RuleType.Directory => $"{neg}Directory '{rule.Target}' must exist",
                RuleType.Process   => $"{neg}Process '{rule.Target}' must be running",
                RuleType.Command   => $"{neg}Command '{rule.Target}' must exit with code 0",
                RuleType.Registry  => $"{neg}Registry key '{rule.Target}' must exist",
                _                  => $"{neg}Check '{rule.Target}'"
            };
            return verb;
        }

        // Registry: value name exists but no data pattern
        if (rule.Type == RuleType.Registry && rule.RegistryValueName is not null
            && rule.ContentConditions.Count == 0)
            return $"{neg}Registry value '{rule.RegistryValueName}' must exist in key '{rule.Target}'";

        var src = rule.Type switch
        {
            RuleType.Command   => $"output of `{rule.Target}`",
            RuleType.Registry  => rule.RegistryValueName is not null
                                   ? $"value '{rule.RegistryValueName}' in key '{rule.Target}'"
                                   : $"registry key '{rule.Target}'",
            RuleType.File      => $"'{rule.Target}'",
            RuleType.Directory => $"files inside '{rule.Target}'",
            _                  => $"'{rule.Target}'"
        };

        if (rule.ContentConditions.Count == 1)
        {
            sb.Append(neg);
            sb.Append(ExplainCondition(rule.ContentConditions[0], src));
        }
        else
        {
            sb.AppendLine($"{neg}A single line in {src} must satisfy ALL of:");
            for (var i = 0; i < rule.ContentConditions.Count; i++)
                sb.Append($"\n           [{i + 1}] {ExplainCondition(rule.ContentConditions[i], src)}");
        }

        return sb.ToString();
    }

    private static string ExplainCondition(ContentCondition c, string source) =>
        c.Operator switch
        {
            ContentOperator.Literal => $"{source} {(c.Negated ? "does NOT contain" : "contains")} literal: \"{c.Pattern}\"",
            ContentOperator.Regex   => $"{source} {(c.Negated ? "must NOT match" : "must match")} regex: `{c.Pattern}`",
            ContentOperator.Numeric => ExplainNumeric(c, source),
            _                       => "unknown condition"
        };

    private static string ExplainNumeric(ContentCondition c, string source)
    {
        var opStr = c.NumericOp switch
        {
            NumericComparison.LessThan           => "less than",
            NumericComparison.LessThanOrEqual    => "less than or equal to",
            NumericComparison.Equal              => "equal to",
            NumericComparison.NotEqual           => "not equal to",
            NumericComparison.GreaterThanOrEqual => "greater than or equal to",
            NumericComparison.GreaterThan        => "greater than",
            _                                    => "compared to"
        };
        var neg = c.Negated ? "NOT " : string.Empty;
        return $"{neg}Numeric value captured by `{c.Pattern}` in {source} must be {opStr} {c.NumericValue}";
    }
}
