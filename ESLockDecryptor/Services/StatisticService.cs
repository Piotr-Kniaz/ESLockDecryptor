namespace ESLockDecryptor.Services;

public class StatisticService
{
    public void IncrementFilesProcessed() => Interlocked.Increment(ref _filesProcessed);
    public void IncrementFilesDecrypted()
    {
        Interlocked.Increment(ref _filesDecrypted);
        Interlocked.Increment(ref _filesProcessed);
    }
    public void IncrementFilesSkipped()
    {
        Interlocked.Increment(ref _filesSkipped);
        Interlocked.Increment(ref _filesProcessed);
    }
    public void IncrementErrors() => Interlocked.Increment(ref _errors);
    public void IncrementWarnings() => Interlocked.Increment(ref _warnings);

    public int FilesProcessed { get => _filesProcessed; }
    public int FilesDecrypted { get => _filesDecrypted; }
    public int FilesSkipped { get => _filesSkipped; }
    public int Errors { get => _errors; }
    public int Warnings { get => _warnings; }

    private int _filesProcessed = 0;
    private int _filesDecrypted = 0;
    private int _filesSkipped = 0;
    private int _errors = 0;
    private int _warnings = 0;
}