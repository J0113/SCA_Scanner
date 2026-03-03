using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SCA_Scanner;

public class ScaFile
{
    public PolicyMeta Policy { get; set; } = new();
    public RequirementsSection? Requirements { get; set; }
    public List<ScaCheck> Checks { get; set; } = [];
}

public class PolicyMeta
{
    public string Id { get; set; } = string.Empty;
    public string File { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public List<string> References { get; set; } = [];
}

public class RequirementsSection
{
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Condition { get; set; } = "all";
    public List<string> Rules { get; set; } = [];
}

public class ScaCheck
{
    public int Id { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Rationale { get; set; } = string.Empty;
    public string Impact { get; set; } = string.Empty;
    public string Remediation { get; set; } = string.Empty;
    public List<string> References { get; set; } = [];
    public object? Compliance { get; set; }  // complex structure, not needed for eval
    public string Condition { get; set; } = "all";
    public List<string> Rules { get; set; } = [];
}

// Result records
public record RuleResult(string Rule, bool Passed, string? Error = null);

public record CheckResult(
    int Id,
    string Title,
    string Condition,
    List<RuleResult> RuleResults,
    bool Passed);