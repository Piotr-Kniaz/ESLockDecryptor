namespace ESLockDecryptor.Services;

public record Options(
    FileSystemInfo? InputPath,
    DirectoryInfo? OutputPath,
    bool ReadOnly,
    bool IgnoreCrc,
    bool Verbose,
    bool Overwrite,
    string? Password,
    string? Key
);