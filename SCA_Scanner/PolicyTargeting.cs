using System.Text.RegularExpressions;

namespace SCA_Scanner;

internal static class PolicyTargeting
{
    private enum TargetOsKind
    {
        Unknown,
        WindowsClient,
        WindowsServer
    }

    private sealed record TargetHint(TargetOsKind Kind, int? ClientMajor, int? ServerYear, string? Edition);

    public static bool PolicyAppliesToThisHost(PolicyMeta policy, string yamlPath, out string whyNot) //thanks gerwin
    {
        whyNot = string.Empty;

        var hint = GuessTarget(policy, yamlPath);
        if (hint.Kind == TargetOsKind.Unknown)
            return true; // don't block if we can't confidently infer the target

        var win = OSInfo.TryGetWindowsInfo();
        if (win is null)
        {
            whyNot = "Policy appears to target Windows, but the current OS is not Windows.";
            return false;
        }

        bool isServer = OSInfo.IsServer(win);

        if (hint.Kind == TargetOsKind.WindowsServer)
        {
            if (!isServer)
            {
                whyNot = $"Policy appears to target Windows Server, but this host is: {OSInfo.Describe(win)}";
                return false;
            }

            if (hint.ServerYear is not null && !win.ProductName.Contains(hint.ServerYear.Value.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                whyNot = $"Policy targets Windows Server {hint.ServerYear}, but this host is: {OSInfo.Describe(win)}";
                return false;
            }

            // Edition hints for server (Datacenter/Standard) are nice-to-have
            if (!string.IsNullOrWhiteSpace(hint.Edition) && !MatchesEdition(win, hint.Edition))
            {
                whyNot = $"Policy targets edition '{hint.Edition}', but this host is: {OSInfo.Describe(win)}";
                return false;
            }

            return true;
        }

        // Windows client (10/11)
        if (isServer)
        {
            whyNot = $"Policy appears to target Windows client, but this host is: {OSInfo.Describe(win)}";
            return false;
        }

        if (hint.ClientMajor is 10)
        {
            // Windows 11 is build >= 22000
            if (OSInfo.IsWindows11Client(win))
            {
                whyNot = $"Policy targets Windows 10, but this host is: {OSInfo.Describe(win)}";
                return false;
            }
        }
        else if (hint.ClientMajor is 11)
        {
            if (!OSInfo.IsWindows11Client(win))
            {
                whyNot = $"Policy targets Windows 11, but this host is: {OSInfo.Describe(win)}";
                return false;
            }
        }

        if (!string.IsNullOrWhiteSpace(hint.Edition) && !MatchesEdition(win, hint.Edition))
        {
            whyNot = $"Policy targets edition '{hint.Edition}', but this host is: {OSInfo.Describe(win)}";
            return false;
        }

        return true;
    }

    private static bool MatchesEdition(OSInfo.WindowsInfo win, string edition)
    {
        // edition values are usually like Enterprise / Professional / Education / Datacenter / Standard
        // We match both ProductName and EditionID because one or the other is typically present.
        return win.EditionId.Contains(edition, StringComparison.OrdinalIgnoreCase)
               || win.ProductName.Contains(edition, StringComparison.OrdinalIgnoreCase);
    }

    private static TargetHint GuessTarget(PolicyMeta policy, string yamlPath)
    {
        // Use multiple fields because different SCA files encode it differently.
        string haystack = string.Join(" ",
            Path.GetFileName(yamlPath),
            policy.Id ?? string.Empty,
            policy.Name ?? string.Empty,
            policy.File ?? string.Empty).ToLowerInvariant();

        // Server hints
        var serverYear = Regex.Match(haystack, @"server[\s_\-]*(20\d{2})");
        if (serverYear.Success && int.TryParse(serverYear.Groups[1].Value, out int year))
        {
            return new TargetHint(TargetOsKind.WindowsServer, ClientMajor: null, ServerYear: year, Edition: GuessEdition(haystack));
        }

        if (haystack.Contains("windows server") || haystack.Contains("winserver") || haystack.Contains("server_"))
        {
            return new TargetHint(TargetOsKind.WindowsServer, ClientMajor: null, ServerYear: null, Edition: GuessEdition(haystack));
        }

        // Client hints
        if (haystack.Contains("win11") || haystack.Contains("windows 11"))
            return new TargetHint(TargetOsKind.WindowsClient, ClientMajor: 11, ServerYear: null, Edition: GuessEdition(haystack));

        if (haystack.Contains("win10") || haystack.Contains("windows 10"))
            return new TargetHint(TargetOsKind.WindowsClient, ClientMajor: 10, ServerYear: null, Edition: GuessEdition(haystack));

        // If it only says "windows" we don't block.
        return new TargetHint(TargetOsKind.Unknown, ClientMajor: null, ServerYear: null, Edition: null);
    }

    private static string? GuessEdition(string haystack)
    {
        // Keep this intentionally conservative: only return an edition when it's very explicit.
        if (haystack.Contains("enterprise")) return "Enterprise";
        if (haystack.Contains("education")) return "Education";
        if (haystack.Contains("professional") || Regex.IsMatch(haystack, @"\bpro\b")) return "Professional";
        if (haystack.Contains("datacenter")) return "Datacenter";
        if (haystack.Contains("standard")) return "Standard";
        return null;
    }
}
