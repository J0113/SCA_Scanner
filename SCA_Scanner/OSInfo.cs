using Microsoft.Win32;

namespace SCA_Scanner;

internal static class OSInfo
{
    internal sealed record WindowsInfo(
        string ProductName,
        string EditionId,
        int BuildNumber,
        string InstallationType,
        string DisplayVersion);

    public static WindowsInfo? TryGetWindowsInfo()
    {
        if (!OperatingSystem.IsWindows())
            return null;

        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
        if (key is null)
            return null;

        string productName = (key.GetValue("ProductName") as string) ?? string.Empty;
        string editionId = (key.GetValue("EditionID") as string) ?? string.Empty;
        string installationType = (key.GetValue("InstallationType") as string) ?? string.Empty;
        string displayVersion = (key.GetValue("DisplayVersion") as string) ?? (key.GetValue("ReleaseId") as string) ?? string.Empty;

        int buildNumber = 0;
        var buildRaw = key.GetValue("CurrentBuildNumber")?.ToString();
        _ = int.TryParse(buildRaw, out buildNumber);

        return new WindowsInfo(
            ProductName: productName,
            EditionId: editionId,
            BuildNumber: buildNumber,
            InstallationType: installationType,
            DisplayVersion: displayVersion);
    }

    public static string Describe(WindowsInfo w)
    {
        string product = w.ProductName;

        // Some Win11 installs still report ProductName as "Windows 10 ...".
        // Build number is the reliable differentiator (Win11 starts at 22000).
        if (!IsServer(w) && w.BuildNumber >= 22000)
        {
            if (product.Contains("Windows 10", StringComparison.OrdinalIgnoreCase))
                product = product.Replace("Windows 10", "Windows 11", StringComparison.OrdinalIgnoreCase);
            else if (!product.Contains("Windows 11", StringComparison.OrdinalIgnoreCase))
                product = $"Windows 11 ({product})";
        }

        string dv = string.IsNullOrWhiteSpace(w.DisplayVersion) ? "" : $" ({w.DisplayVersion})";
        string ed = string.IsNullOrWhiteSpace(w.EditionId) ? "" : $", {w.EditionId}";
        string it = string.IsNullOrWhiteSpace(w.InstallationType) ? "" : $", {w.InstallationType}";
        return $"{product}{dv}{ed} build {w.BuildNumber}{it}".Trim();
    }

    public static bool IsServer(WindowsInfo w)
        => w.InstallationType.Equals("Server", StringComparison.OrdinalIgnoreCase)
           || w.ProductName.Contains("server", StringComparison.OrdinalIgnoreCase);

    public static bool IsWindows11Client(WindowsInfo w)
        // Windows 11 is still version 10.0 under the hood; build number is the easiest.
        => !IsServer(w) && w.BuildNumber >= 22000;
}
