namespace ESLockDecryptor.Services;

internal class LogBuffer
{
    private static readonly Lock _consoleLock = new();
    private readonly List<string> _logBuffer = [];

    public void AddLine(string line)
    {
        _logBuffer.Add(line);
    }


    public void PrintBuffer()
    {
        lock (_consoleLock)
        {
            foreach (var line in _logBuffer)
            {
                if (line.Contains("[WARNING]"))
                    Console.ForegroundColor = ConsoleColor.Yellow;
                else if (line.Contains("[ERROR]"))
                    Console.ForegroundColor = ConsoleColor.Red;
                else if (line.Contains("[SUCCESS]"))
                    Console.ForegroundColor = ConsoleColor.Green;

                Console.WriteLine(line);
                Console.ResetColor();
            }
        }
    }
}