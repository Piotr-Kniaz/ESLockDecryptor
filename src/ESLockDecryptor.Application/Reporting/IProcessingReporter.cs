namespace ESLockDecryptor.Application.Reporting;

public interface IProcessingReporter
{
    IProcessingReportScope BeginScope();
    void Info(string message);
    void Success(string message);
    void Warning(string message);
    void Error(string message);
}

public interface IProcessingReportScope : IDisposable
{
    void Info(string message);
    void Success(string message);
    void Warning(string message);
    void Error(string message);
}