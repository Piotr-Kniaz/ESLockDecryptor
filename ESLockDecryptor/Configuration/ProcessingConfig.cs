namespace ESLockDecryptor.Configuration;

public record ProcessingConfig(
    FileSystemInfo InputPath,
    DirectoryInfo? OutputPath,
    bool Verbose,
    bool Overwrite,
    bool ReadOnly,
    bool IgnoreCrc,
    string? Password,
    string? Key,
    bool Heuristic,
    RawDecryptConfig? RawDecryptConfig
);