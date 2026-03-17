namespace SCAScanner;

/// <summary>
/// File-based reporter. Writes plain text (no colors) to a file.
/// Always uses Detailed output level so log files are always complete.
/// </summary>
public sealed class FileReporter : BaseReporter, IDisposable
{
    private readonly StreamWriter _writer;

    public FileReporter(string filePath) : base(OutputLevel.Detailed)
    {
        _writer = new StreamWriter(filePath, append: false, encoding: System.Text.Encoding.UTF8);
    }

    protected override void Write(string text, ConsoleColor? color = null)
        => _writer.Write(text);

    protected override void WriteLine(string text = "", ConsoleColor? color = null)
        => _writer.WriteLine(text);

    public void Dispose()
    {
        _writer.Flush();
        _writer.Dispose();
    }
}
