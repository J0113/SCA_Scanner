namespace SCAScanner;

internal static class StringUtils
{
    public static string Truncate(string text, int maxLength) =>
        text.Length <= maxLength ? text : text[..maxLength] + "…";
}
