namespace SCAScanner;

/// <summary>
/// Console-based reporter with colored output. Extends BaseReporter with
/// Console color support.
/// </summary>
public sealed class ConsoleReporter : BaseReporter
{
    public ConsoleReporter(OutputLevel level = OutputLevel.Standard) : base(level) { }

    protected override void Write(string text, ConsoleColor? color = null)
    {
        if (color.HasValue) Console.ForegroundColor = color.Value;
        Console.Write(text);
        Console.ResetColor();
    }

    protected override void WriteLine(string text = "", ConsoleColor? color = null)
    {
        if (color.HasValue) Console.ForegroundColor = color.Value;
        Console.WriteLine(text);
        Console.ResetColor();
    }
}
