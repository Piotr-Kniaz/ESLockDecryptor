namespace ESLockDecryptor.Logging;

public interface ILogger
{
    void AddInfo(string message);
    void AddSuccess(string message);
    void AddWarning(string message);
    void AddError(string message);
}