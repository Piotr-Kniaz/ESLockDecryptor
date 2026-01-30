namespace ESLockDecryptor.Services;

public record Options(
    FileSystemInfo? InputPath,
    DirectoryInfo? OutputPath,
    bool ExtractKeyOnly,
    bool IgnoreCrc,
    bool Verbose,
    bool Overwrite,
    string? Password,
    string? Key
);