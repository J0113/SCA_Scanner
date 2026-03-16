namespace SCAScanner;

/// <summary>
/// Abstraction for reporting/output, allowing multiple output formats (Console, JSON, CSV, etc.).
/// Decouples output logic from business logic.
/// </summary>
public interface IReporter
{
    // =========================================================================
    // UI Structure
    // =========================================================================

    void PrintBanner();
    void PrintHelp();

    // =========================================================================
    // Policy Execution Context
    // =========================================================================

    void PrintPolicyHeader(SCAPolicy policy, string platform);
    void PrintRequirementsSection(Check requirementsCheck, PolicyVariables? variables, CheckResult requirementsResult);

    // =========================================================================
    // Check Execution
    // =========================================================================

    void PrintCheckHeader(Check check);
    void PrintRuleExplanations(List<ParsedRule> parsedRules, Check check, PolicyVariables? variables);
    void PrintRuleResults(IReadOnlyList<RuleResult> ruleResults);
    void PrintCheckResult(Check check, CheckResult result, int totalPassed, int totalFailed);

    // =========================================================================
    // Summary
    // =========================================================================

    void PrintScanSummary(int passed, int failed, List<ScanCheckResult> checkResults);

    // =========================================================================
    // Directory Scanning
    // =========================================================================

    void PrintDiscoveryHeader(string directoryPath, int foundCount);
    void PrintRequirementCheckLine(string fileName, bool met, string? note);
    void PrintApplicablePoliciesLine(int applicableCount);
    void PrintPolicyExecutionHeader(int index, int total, string policyFileName);
    void PrintDirectoryScanComplete(int totalPolicies, int failedPolicies);

    // =========================================================================
    // Error Messages
    // =========================================================================

    void PrintError(string message);
    void PrintNoPolicesFound(string directoryPath);
}
