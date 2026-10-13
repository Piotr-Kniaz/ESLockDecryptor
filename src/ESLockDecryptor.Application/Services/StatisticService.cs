namespace ESLockDecryptor.Application.Services;

internal sealed class StatisticService
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

    public int FilesProcessed => _filesProcessed;
    public int FilesDecrypted => _filesDecrypted;
    public int FilesSkipped => _filesSkipped;
    public int Errors => _errors;
    public int Warnings => _warnings;

    private int _filesProcessed;
    private int _filesDecrypted;
    private int _filesSkipped;
    private int _errors;
    private int _warnings;
}