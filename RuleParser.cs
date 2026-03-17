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
    public bool             Negated       { get; init; }
    public ContentOperator  Operator      { get; init; }
    public string           Pattern       { get; init; } = string.Empty;
    /// <summary>True if this content condition is malformed and cannot be evaluated.</summary>
    public bool             Invalid       { get; init; }
    /// <summary>Reason why this condition is invalid (if Invalid is true).</summary>
    public string?          InvalidReason { get; init; }
    // Numeric only
    public NumericComparison? NumericOp   { get; init; }
    public double?          NumericValue  { get; init; }
}

// ---------------------------------------------------------------------------
// A fully parsed rule string
// ---------------------------------------------------------------------------
public sealed class ParsedRule
{
    /// <summary>True when the rule is prefixed with "not " or "!".</summary>
    public bool                   Negated           { get; init; }
    public RuleType               Type              { get; init; }
    /// <summary>File path, process name, command string, or registry key path.</summary>
    public string                 Target            { get; init; } = string.Empty;
    public bool                   HasContentCheck   { get; init; }
    /// <summary>True if the rule definition is malformed/incomplete and cannot be executed.</summary>
    public bool                   Invalid           { get; init; }
    /// <summary>Reason why the rule is invalid (if Invalid is true).</summary>
    public string?                InvalidReason     { get; init; }
    /// <summary>
    /// Registry only: the value name in the 3-part format
    /// r:KEY -> ValueName -> DataPattern
    /// </summary>
    public string?                RegistryValueName { get; init; }
    /// <summary>One or more conditions connected by && in the original rule string.</summary>
    public List<ContentCondition> ContentConditions { get; init; } = [];
    public string                 OriginalText      { get; init; } = string.Empty;
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
    public static ParsedRule Parse(string raw, PolicyVariables? variables = null)
    {
        string original = raw;

        // Expand $variables
        if (variables?.HasVariables == true)
            foreach (var (k, v) in variables.Values)
                raw = raw.Replace(k, v);

        // ── Overall negation ─────────────────────────────────────────────
        // Wazuh supports both "not " prefix and leading "!" (for non-registry)
        bool negated = false;
        if (raw.StartsWith("not ", StringComparison.OrdinalIgnoreCase))
        {
            negated = true;
            raw = raw[4..];
        }
        // "!" negation only when NOT followed by a content-operator prefix
        else if (raw.Length > 2 && raw[0] == '!' && raw[1] != 'r' && raw[1] != 'n')
        {
            negated = true;
            raw = raw[1..];
        }

        // ── Rule type prefix ──────────────────────────────────────────────
        RuleType type;
        if      (raw.StartsWith("f:")) { type = RuleType.File;      raw = raw[2..]; }
        else if (raw.StartsWith("d:")) { type = RuleType.Directory;  raw = raw[2..]; }
        else if (raw.StartsWith("p:")) { type = RuleType.Process;    raw = raw[2..]; }
        else if (raw.StartsWith("c:")) { type = RuleType.Command;    raw = raw[2..]; }
        else if (raw.StartsWith("r:")) { type = RuleType.Registry;   raw = raw[2..]; }
        else
            return new ParsedRule
            {
                OriginalText  = original,
                Negated       = negated,
                Invalid       = true,
                InvalidReason = $"Unknown rule prefix in '{original}' — must start with f:, d:, p:, c:, or r:"
            };

        // ── Target vs content ─────────────────────────────────────────────
        string target;
        bool hasContentCheck       = false;
        string? registryValueName  = null;
        List<ContentCondition> conditions = [];

        if (type == RuleType.Registry)
        {
            // Registry uses a 3-part format:  KEY -> ValueName -> DataPattern
            // All three parts separated by " -> "; DataPattern is optional.
            string[] regParts = raw.Split(ArrowSeparator, 3, StringSplitOptions.None);
            target = regParts[0].Trim();
            if (regParts.Length >= 2)
            {
                hasContentCheck   = true;
                registryValueName = regParts[1].Trim();
            }
            if (regParts.Length >= 3)
            {
                // Multiple conditions separated by " && "
                foreach (string seg in regParts[2].Split(AndSeparator, StringSplitOptions.None))
                    conditions.Add(ParseContentCondition(seg.Trim()));
            }
        }
        else
        {
            // Split on the FIRST occurrence of " -> "
            string[] parts = raw.Split(ArrowSeparator, 2, StringSplitOptions.None);
            target = parts[0].Trim();
            if (parts.Length == 2)
            {
                hasContentCheck = true;
                // Each segment separated by " && " is an independent condition
                foreach (string seg in parts[1].Split(AndSeparator, StringSplitOptions.None))
                    conditions.Add(ParseContentCondition(seg.Trim()));
            }
        }

        // Propagate invalidity from content conditions
        ContentCondition? invalidCondition = conditions.FirstOrDefault(c => c.Invalid);

        return new ParsedRule
        {
            OriginalText      = original,
            Negated           = negated,
            Type              = type,
            Target            = target,
            HasContentCheck   = hasContentCheck,
            RegistryValueName = registryValueName,
            ContentConditions = conditions,
            Invalid           = invalidCondition is not null,
            InvalidReason     = invalidCondition?.InvalidReason
        };
    }

    // ── Content condition parser ──────────────────────────────────────────
    private static ContentCondition ParseContentCondition(string s)
    {
        bool negated = s.StartsWith('!');
        if (negated) s = s[1..];

        if (s.StartsWith("r:"))
            return new ContentCondition { Negated = negated, Operator = ContentOperator.Regex, Pattern = s[2..] };

        if (s.StartsWith("n:"))
            return ParseNumericCondition(negated, s[2..]);

        return new ContentCondition { Negated = negated, Operator = ContentOperator.Literal, Pattern = s };
    }

    // Format: REGEX_WITH_(\d+) compare OPERATOR VALUE
    private static ContentCondition ParseNumericCondition(bool negated, string s)
    {
        const string sep = " compare ";
        int idx = s.IndexOf(sep, StringComparison.Ordinal);

        if (idx < 0)
            return new ContentCondition
            {
                Negated = negated, Operator = ContentOperator.Numeric, Pattern = s,
                Invalid = true, InvalidReason = "Incomplete numeric condition: missing 'compare OPERATOR VALUE'"
            };

        string pattern = s[..idx];
        string rest    = s[(idx + sep.Length)..].Trim();

        if (string.IsNullOrWhiteSpace(rest))
            return new ContentCondition
            {
                Negated = negated, Operator = ContentOperator.Numeric, Pattern = pattern,
                Invalid = true, InvalidReason = "Incomplete numeric condition: missing operator after 'compare'"
            };

        string[] comparison = rest.Split(' ', 2);

        // Map the operator token in a single pass — null means unrecognised
        NumericComparison? parsedOp = comparison[0] switch
        {
            "<"  => NumericComparison.LessThan,
            "<=" => NumericComparison.LessThanOrEqual,
            "==" => NumericComparison.Equal,
            "!=" => NumericComparison.NotEqual,
            ">=" => NumericComparison.GreaterThanOrEqual,
            ">"  => NumericComparison.GreaterThan,
            _    => (NumericComparison?)null
        };

        if (parsedOp is null)
            return new ContentCondition
            {
                Negated = negated, Operator = ContentOperator.Numeric, Pattern = pattern,
                Invalid = true,
                InvalidReason = $"Incomplete numeric condition: '{comparison[0]}' is not a valid operator"
            };

        if (comparison.Length < 2)
            return new ContentCondition
            {
                Negated = negated, Operator = ContentOperator.Numeric, Pattern = pattern,
                Invalid = true, InvalidReason = "Incomplete numeric condition: missing value after operator"
            };

        if (!double.TryParse(comparison[1], out double v))
            return new ContentCondition
            {
                Negated = negated, Operator = ContentOperator.Numeric, Pattern = pattern,
                Invalid = true,
                InvalidReason = $"Invalid numeric value '{comparison[1]}': must be a number"
            };

        return new ContentCondition
        {
            Negated      = negated,
            Operator     = ContentOperator.Numeric,
            Pattern      = pattern,
            NumericOp    = parsedOp,
            NumericValue = v
        };
    }

    // =========================================================================
    // Human-readable explanation (called BEFORE execution to explain intent)
    // =========================================================================

    public static string Explain(ParsedRule rule)
    {
        StringBuilder sb = new();
        string neg = rule.Negated ? "NOT " : string.Empty;

        if (!rule.HasContentCheck)
        {
            string verb = rule.Type switch
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

        string src = rule.Type switch
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
            for (int i = 0; i < rule.ContentConditions.Count; i++)
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
        string opStr = c.NumericOp switch
        {
            NumericComparison.LessThan           => "less than",
            NumericComparison.LessThanOrEqual    => "less than or equal to",
            NumericComparison.Equal              => "equal to",
            NumericComparison.NotEqual           => "not equal to",
            NumericComparison.GreaterThanOrEqual => "greater than or equal to",
            NumericComparison.GreaterThan        => "greater than",
            _                                    => "compared to"
        };
        string neg = c.Negated ? "NOT " : string.Empty;
        return $"{neg}Numeric value captured by `{c.Pattern}` in {source} must be {opStr} {c.NumericValue}";
    }
}
