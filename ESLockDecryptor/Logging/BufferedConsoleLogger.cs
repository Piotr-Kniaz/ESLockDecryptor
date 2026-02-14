namespace ESLockDecryptor.Logging;

public class BufferedConsoleLogger : ILogger
{
    public void AddInfo(string message) => _buffer.Add((null, message));
    public void AddSuccess(string message) => _buffer.Add((ConsoleColor.Green, $"[SUCCESS] {message}"));
    public void AddWarning(string message) => _buffer.Add((ConsoleColor.Yellow, $"[WARNING] {message}"));
    public void AddError(string message) => _buffer.Add((ConsoleColor.Red, $"[ERROR] {message}"));

    public void Flush()
    {
        lock (_consoleLock)
        {
            foreach (var (color, text) in _buffer)
            {
                if (color is not null)
                    Console.ForegroundColor = (ConsoleColor)color;
                Console.WriteLine(text);
                Console.ResetColor();
            }
        }
    }

    private readonly List<(ConsoleColor? Color, string Text)> _buffer = [];
    private static readonly Lock _consoleLock = new();
}