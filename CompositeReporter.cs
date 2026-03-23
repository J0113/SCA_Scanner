namespace SCAScanner;

/// <summary>
/// Multiplexes all reporting calls to a set of reporters. Each reporter
/// only receives calls for the sub-interfaces it implements — reporters that
/// don't implement a given sub-interface are silently skipped for those calls.
/// Accepts any object; sorts it into sub-interface buckets at construction time.
/// Disposes any <see cref="IDisposable"/> reporters when disposed.
/// </summary>
public sealed class CompositeReporter : IReporter, IDisposable
{
    private readonly IPolicyReporter[]    _policy;
    private readonly ICheckReporter[]     _check;
    private readonly ISummaryReporter[]   _summary;
    private readonly IDirectoryReporter[] _directory;
    private readonly IErrorReporter[]     _error;
    private readonly IDisposable[]        _disposables;

    public CompositeReporter(params object[] reporters)
    {
        _policy      = reporters.OfType<IPolicyReporter>().ToArray();
        _check       = reporters.OfType<ICheckReporter>().ToArray();
        _summary     = reporters.OfType<ISummaryReporter>().ToArray();
        _directory   = reporters.OfType<IDirectoryReporter>().ToArray();
        _error       = reporters.OfType<IErrorReporter>().ToArray();
        _disposables = reporters.OfType<IDisposable>().ToArray();
    }

    // ── IPolicyReporter ───────────────────────────────────────────────────

    public void PrintBanner()
    { foreach (var r in _policy) r.PrintBanner(); }

    public void PrintHelp()
    { foreach (var r in _policy) r.PrintHelp(); }

    public void PrintPolicyHeader(SCAPolicy policy, string platform)
    { foreach (var r in _policy) r.PrintPolicyHeader(policy, platform); }

    public void PrintRequirementsSection(Check requirementsCheck, PolicyVariables? variables, CheckResult requirementsResult)
    { foreach (var r in _policy) r.PrintRequirementsSection(requirementsCheck, variables, requirementsResult); }

    // ── ICheckReporter ────────────────────────────────────────────────────

    public void PrintCheckHeader(Check check)
    { foreach (var r in _check) r.PrintCheckHeader(check); }

    public void PrintRuleExplanations(List<ParsedRule> parsedRules, Check check, PolicyVariables? variables)
    { foreach (var r in _check) r.PrintRuleExplanations(parsedRules, check, variables); }

    public void PrintRuleResults(IReadOnlyList<RuleResult> ruleResults)
    { foreach (var r in _check) r.PrintRuleResults(ruleResults); }

    public void PrintCheckResult(Check check, CheckResult result, int totalPassed, int totalFailed)
    { foreach (var r in _check) r.PrintCheckResult(check, result, totalPassed, totalFailed); }

    // ── ISummaryReporter ──────────────────────────────────────────────────

    public void PrintScanSummary(int passed, int failed, int invalid, List<ScanCheckResult> checkResults)
    { foreach (var r in _summary) r.PrintScanSummary(passed, failed, invalid, checkResults); }

    // ── IDirectoryReporter ────────────────────────────────────────────────

    public void PrintDiscoveryHeader(string directoryPath, int foundCount)
    { foreach (var r in _directory) r.PrintDiscoveryHeader(directoryPath, foundCount); }

    public void PrintRequirementCheckLine(string fileName, bool met, string? note)
    { foreach (var r in _directory) r.PrintRequirementCheckLine(fileName, met, note); }

    public void PrintApplicablePoliciesLine(int applicableCount)
    { foreach (var r in _directory) r.PrintApplicablePoliciesLine(applicableCount); }

    public void PrintPolicyExecutionHeader(int index, int total, string policyFileName)
    { foreach (var r in _directory) r.PrintPolicyExecutionHeader(index, total, policyFileName); }

    public void PrintDirectoryScanComplete(int totalPolicies, int failedPolicies)
    { foreach (var r in _directory) r.PrintDirectoryScanComplete(totalPolicies, failedPolicies); }

    // ── IErrorReporter ────────────────────────────────────────────────────

    public void PrintError(string message)
    { foreach (var r in _error) r.PrintError(message); }

    public void PrintWarning(string message)
    { foreach (var r in _error) r.PrintWarning(message); }

    public void PrintInfo(string message)
    { foreach (var r in _error) r.PrintInfo(message); }

    public void PrintNoPolicesFound(string directoryPath)
    { foreach (var r in _error) r.PrintNoPolicesFound(directoryPath); }

    // ── IDisposable ───────────────────────────────────────────────────────

    public void Dispose()
    {
        foreach (var d in _disposables) d.Dispose();
    }
}
