namespace ESLockDecryptor.Configuration;

public record RawDecryptConfig
{
    public RawDecryptConfig() =>
        Mode = RawDecryptMode.Auto;

    public RawDecryptConfig(RawDecryptMode mode) =>
        Mode = mode;

    public RawDecryptConfig(RawDecryptMode mode, int? size)
    {
        if (mode == RawDecryptMode.Partial && size < 0)
            throw new ArgumentException("Encrypted block size must be greater than zero.", nameof(size));

        Mode = mode;
        EncryptedBlockSize = size;
    }
    public RawDecryptMode Mode { get; }
    public int? EncryptedBlockSize { get; }
}