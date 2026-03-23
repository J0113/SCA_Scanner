namespace SCAScanner;

// ---------------------------------------------------------------------------
// Focused sub-interfaces (Interface Segregation Principle)
// ---------------------------------------------------------------------------

/// <summary>Banner, help text, and per-policy execution context.</summary>
public interface IPolicyReporter
{
    void PrintBanner();
    void PrintHelp();
    void PrintPolicyHeader(SCAPolicy policy, string platform);
    void PrintRequirementsSection(Check requirementsCheck, PolicyVariables? variables, CheckResult requirementsResult);
}

/// <summary>Per-check detail output: header, rule explanations, rule results, and final result.</summary>
public interface ICheckReporter
{
    void PrintCheckHeader(Check check);
    void PrintRuleExplanations(List<ParsedRule> parsedRules, Check check, PolicyVariables? variables);
    void PrintRuleResults(IReadOnlyList<RuleResult> ruleResults);
    void PrintCheckResult(Check check, CheckResult result, int totalPassed, int totalFailed);
}

/// <summary>End-of-scan summary table.</summary>
public interface ISummaryReporter
{
    void PrintScanSummary(int passed, int failed, int invalid, List<ScanCheckResult> checkResults);
}

/// <summary>Directory-scan discovery and progress output.</summary>
public interface IDirectoryReporter
{
    void PrintDiscoveryHeader(string directoryPath, int foundCount);
    void PrintRequirementCheckLine(string fileName, bool met, string? note);
    void PrintApplicablePoliciesLine(int applicableCount);
    void PrintPolicyExecutionHeader(int index, int total, string policyFileName);
    void PrintDirectoryScanComplete(int totalPolicies, int failedPolicies);
}

/// <summary>Error and diagnostic messages.</summary>
public interface IErrorReporter
{
    void PrintError(string message);
    void PrintWarning(string message);
    void PrintInfo(string message);
    void PrintNoPolicesFound(string directoryPath);
}

// ---------------------------------------------------------------------------
// Composite interface — no breaking change for existing callers
// ---------------------------------------------------------------------------

/// <summary>
/// Full reporter contract. Extends all sub-interfaces so existing code that
/// depends on <see cref="IReporter"/> continues to work without modification.
/// </summary>
public interface IReporter
    : IPolicyReporter, ICheckReporter, ISummaryReporter, IDirectoryReporter, IErrorReporter
{ }
