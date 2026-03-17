namespace SCAScanner;

using YamlDotNet.Serialization;

// ---------------------------------------------------------------------------
// Check status enumeration
// ---------------------------------------------------------------------------

/// <summary>Status of a check result: Passed, Failed, or Invalid (unexecutable).</summary>
public enum CheckStatus
{
    Passed,
    Failed,
    Invalid
}

// ---------------------------------------------------------------------------
// Rule check result
// ---------------------------------------------------------------------------

/// <summary>Result of evaluating a single rule, with status and detail message.</summary>
public sealed class RuleCheckResult
{
    public CheckStatus Status { get; set; }
    public string Detail { get; set; } = string.Empty;
}

// ---------------------------------------------------------------------------
// Policy variables for substitution (e.g., $hosts -> /etc/hosts)
// ---------------------------------------------------------------------------
public sealed class PolicyVariables
{
    /// <summary>
    /// Mapping of variable names (e.g., "$hosts") to their values (e.g., "/etc/hosts").
    /// Used for variable substitution in rule strings.
    /// </summary>
    public Dictionary<string, string> Values { get; set; } = new();

    /// <summary>
    /// Determines if this variables collection has any entries.
    /// </summary>
    public bool HasVariables => Values.Count > 0;
}

// ---------------------------------------------------------------------------
// Top-level policy file (YAML root)
// ---------------------------------------------------------------------------
public sealed class SCAPolicy
{
    public PolicyMetadata Policy    { get; set; } = new();
    public Requirements?  Requirements { get; set; }

    /// <summary>
    /// YAML-mapped variables (deserialized as Dictionary).
    /// Converted to PolicyVariables on access via Variables property.
    /// </summary>
    [YamlMember(Alias = "variables")]
    public Dictionary<string, string>? VariablesDict { get; set; }

    /// <summary>
    /// Parsed and wrapped variables for use throughout the application.
    /// </summary>
    [YamlIgnore]
    public PolicyVariables? Variables
    {
        get
        {
            if (VariablesDict is null) return null;
            return new PolicyVariables { Values = VariablesDict };
        }
    }

    public List<Check>    Checks   { get; set; } = [];
}

// ---------------------------------------------------------------------------
// policy: section
// ---------------------------------------------------------------------------
public sealed class PolicyMetadata
{
    public string       Id          { get; set; } = string.Empty;
    public string       File        { get; set; } = string.Empty;
    public string       Name        { get; set; } = string.Empty;
    public string       Description { get; set; } = string.Empty;
    public List<string>? References { get; set; }
}

// ---------------------------------------------------------------------------
// requirements: section  — must pass before any checks run
// ---------------------------------------------------------------------------
public sealed class Requirements
{
    public string       Title       { get; set; } = string.Empty;
    public string       Description { get; set; } = string.Empty;
    /// <summary>all | any | none</summary>
    public string       Condition   { get; set; } = "any";
    public List<string> Rules       { get; set; } = [];
}

// ---------------------------------------------------------------------------
// checks: list item
// ---------------------------------------------------------------------------
public sealed class Check
{
    public int          Id          { get; set; }
    public string       Title       { get; set; } = string.Empty;
    public string       Description { get; set; } = string.Empty;
    public string       Rationale   { get; set; } = string.Empty;
    public string       Remediation { get; set; } = string.Empty;
    /// <summary>all | any | none</summary>
    public string       Condition   { get; set; } = "all";
    public List<string> Rules       { get; set; } = [];
}

/// <summary>
/// Represents the result of executing a single check during a scan.
/// Used for reporting and summarization.
/// </summary>
public sealed class ScanCheckResult
{
    /// <summary>Check identifier.</summary>
    public required int Id { get; init; }

    /// <summary>Check title/name.</summary>
    public required string Title { get; init; }

    /// <summary>Status of the check result.</summary>
    public required CheckStatus Status { get; init; }

    /// <summary>Reason for the result (e.g., "Condition 'ALL': 19/19 rules passed").</summary>
    public required string Reason { get; init; }
}