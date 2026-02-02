namespace ESLockDecryptor.Models;

public record class RawDecryptOptions
{
    public RawDecryptOptions(RawDecryptMode mode = RawDecryptMode.Auto, int? size = null)
    {
        if (mode == RawDecryptMode.Partial)
        {
            if (size <= 0)
                throw new ArgumentException("Encrypted block size must be greater than zero.", nameof(size));

            size ??= 1024;
        }

        Mode = mode;
        EncryptedBlockSize = size;
    }
    public RawDecryptMode Mode { get; init; }
    public int? EncryptedBlockSize { get; init; }
}

public enum RawDecryptMode
{
    Auto,
    Full,
    Partial
}