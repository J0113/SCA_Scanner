namespace SCAScanner;

// ---------------------------------------------------------------------------
// Top-level policy file (YAML root)
// ---------------------------------------------------------------------------
public sealed class SCAPolicy
{
    public PolicyMetadata Policy    { get; set; } = new();
    public Requirements?  Requirements { get; set; }
    public Dictionary<string, string>? Variables { get; set; }
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
