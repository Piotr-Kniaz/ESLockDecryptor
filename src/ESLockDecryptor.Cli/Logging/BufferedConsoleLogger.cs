using ESLockDecryptor.Core.Logging;

namespace ESLockDecryptor.Cli.Logging;

public class BufferedConsoleLogger : ILogger
{
    public void AddInfo(string message) => Add(null, message);
    public void AddSuccess(string message) => Add(ConsoleColor.Green, $"[SUCCESS] {message}");
    public void AddWarning(string message) => Add(ConsoleColor.Yellow, $"[WARNING] {message}");
    public void AddError(string message) => Add(ConsoleColor.Red, $"[ERROR] {message}");

    public void Flush()
    {
        lock (_bufferLock)
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

    private void Add(ConsoleColor? color, string text)
    {
        lock (_bufferLock)
        {
            _buffer.Add((color, text));
        }
    }

    private readonly List<(ConsoleColor? Color, string Text)> _buffer = [];
    private readonly Lock _bufferLock = new();
}