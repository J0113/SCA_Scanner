namespace SCAScanner;

/// <summary>
/// Composite reporter that delegates all calls to multiple IReporter instances.
/// Useful for writing to both the console and a log file simultaneously.
/// Disposes any IDisposable reporters when disposed.
/// </summary>
public sealed class CompositeReporter : IReporter, IDisposable
{
    private readonly IReporter[] _reporters;

    public CompositeReporter(params IReporter[] reporters)
    {
        _reporters = reporters;
    }

    public void PrintBanner()
    { foreach (var r in _reporters) r.PrintBanner(); }

    public void PrintHelp()
    { foreach (var r in _reporters) r.PrintHelp(); }

    public void PrintPolicyHeader(SCAPolicy policy, string platform)
    { foreach (var r in _reporters) r.PrintPolicyHeader(policy, platform); }

    public void PrintRequirementsSection(Check requirementsCheck, PolicyVariables? variables, CheckResult requirementsResult)
    { foreach (var r in _reporters) r.PrintRequirementsSection(requirementsCheck, variables, requirementsResult); }

    public void PrintCheckHeader(Check check)
    { foreach (var r in _reporters) r.PrintCheckHeader(check); }

    public void PrintRuleExplanations(List<ParsedRule> parsedRules, Check check, PolicyVariables? variables)
    { foreach (var r in _reporters) r.PrintRuleExplanations(parsedRules, check, variables); }

    public void PrintRuleResults(IReadOnlyList<RuleResult> ruleResults)
    { foreach (var r in _reporters) r.PrintRuleResults(ruleResults); }

    public void PrintCheckResult(Check check, CheckResult result, int totalPassed, int totalFailed)
    { foreach (var r in _reporters) r.PrintCheckResult(check, result, totalPassed, totalFailed); }

    public void PrintScanSummary(int passed, int failed, int invalid, List<ScanCheckResult> checkResults)
    { foreach (var r in _reporters) r.PrintScanSummary(passed, failed, invalid, checkResults); }

    public void PrintDiscoveryHeader(string directoryPath, int foundCount)
    { foreach (var r in _reporters) r.PrintDiscoveryHeader(directoryPath, foundCount); }

    public void PrintRequirementCheckLine(string fileName, bool met, string? note)
    { foreach (var r in _reporters) r.PrintRequirementCheckLine(fileName, met, note); }

    public void PrintApplicablePoliciesLine(int applicableCount)
    { foreach (var r in _reporters) r.PrintApplicablePoliciesLine(applicableCount); }

    public void PrintPolicyExecutionHeader(int index, int total, string policyFileName)
    { foreach (var r in _reporters) r.PrintPolicyExecutionHeader(index, total, policyFileName); }

    public void PrintDirectoryScanComplete(int totalPolicies, int failedPolicies)
    { foreach (var r in _reporters) r.PrintDirectoryScanComplete(totalPolicies, failedPolicies); }

    public void PrintError(string message)
    { foreach (var r in _reporters) r.PrintError(message); }

    public void PrintNoPolicesFound(string directoryPath)
    { foreach (var r in _reporters) r.PrintNoPolicesFound(directoryPath); }

    public void Dispose()
    {
        foreach (var r in _reporters)
            if (r is IDisposable d) d.Dispose();
    }
}
