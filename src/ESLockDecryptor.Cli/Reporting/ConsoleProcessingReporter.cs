using ESLockDecryptor.Application.Reporting;

namespace ESLockDecryptor.Cli.Reporting;

public class ConsoleProcessingReporter : IProcessingReporter
{
    public IProcessingReportScope BeginScope() => new ConsoleProcessingReportScope(this);

    public void Info(string message) => Write(null, message);
    public void Success(string message) => Write(ConsoleColor.Green, $"[SUCCESS] {message}");
    public void Warning(string message) => Write(ConsoleColor.Yellow, $"[WARNING] {message}");
    public void Error(string message) => Write(ConsoleColor.Red, $"[ERROR] {message}");

    private void WriteBatch(IReadOnlyList<(ConsoleColor? Color, string Text)> messages)
    {
        lock (_consoleLock)
        {
            foreach (var (color, text) in messages)
                WriteCore(color, text);
        }
    }

    private void Write(ConsoleColor? color, string text)
    {
        lock (_consoleLock)
            WriteCore(color, text);
    }

    private static void WriteCore(ConsoleColor? color, string text)
    {
        if (color is not null)
            Console.ForegroundColor = color.Value;
        Console.WriteLine(text);
        Console.ResetColor();
    }

    private readonly Lock _consoleLock = new();

    private sealed class ConsoleProcessingReportScope(ConsoleProcessingReporter reporter) : IProcessingReportScope
    {
        public void Info(string message) => Add(null, message);
        public void Success(string message) => Add(ConsoleColor.Green, $"[SUCCESS] {message}");
        public void Warning(string message) => Add(ConsoleColor.Yellow, $"[WARNING] {message}");
        public void Error(string message) => Add(ConsoleColor.Red, $"[ERROR] {message}");

        public void Dispose() => reporter.WriteBatch(_messages);

        private void Add(ConsoleColor? color, string text) => _messages.Add((color, text));

        private readonly List<(ConsoleColor? Color, string Text)> _messages = [];
    }
}