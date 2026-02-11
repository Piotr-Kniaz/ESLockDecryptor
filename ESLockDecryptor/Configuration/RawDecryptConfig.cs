namespace ESLockDecryptor.Configuration;

public record RawDecryptConfig
{
    public RawDecryptConfig(RawDecryptMode mode = RawDecryptMode.Auto, int? size = null)
    {
        if (mode == RawDecryptMode.Partial && size < 0)
            throw new ArgumentException("Encrypted block size must be greater than zero.", nameof(size));

        Mode = mode;
        EncryptedBlockSize = size;
    }
    public RawDecryptMode Mode { get; }
    public int? EncryptedBlockSize { get; }
}

public enum RawDecryptMode
{
    Auto,
    Full,
    Partial
}