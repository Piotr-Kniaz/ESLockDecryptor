namespace ESLockDecryptor.Core.Configuration;

/// <summary>Specifies the mode and block size for raw decryption.</summary>
public sealed record RawDecryptConfig
{
    /// <summary>Creates settings using automatic mode selection.</summary>
    public RawDecryptConfig() =>
        Mode = RawDecryptMode.Auto;

    /// <summary>Creates settings for the specified mode.</summary>
    /// <param name="mode">The raw decryption mode.</param>
    public RawDecryptConfig(RawDecryptMode mode)
    {
        ArgumentNullException.ThrowIfNull(mode);
        Mode = mode;
    }

    /// <summary>Creates settings for the specified mode and block size.</summary>
    /// <param name="mode">The raw decryption mode.</param>
    /// <param name="size">The encrypted block size for partial mode.</param>
    public RawDecryptConfig(RawDecryptMode mode, int? size)
    {
        ArgumentNullException.ThrowIfNull(mode);

        if (mode == RawDecryptMode.Partial && size <= 0)
            throw new ArgumentException("Encrypted block size must be greater than zero.", nameof(size));

        Mode = mode;
        EncryptedBlockSize = size;
    }
    /// <summary>Gets the selected raw decryption mode.</summary>
    public RawDecryptMode Mode { get; }
    /// <summary>Gets the encrypted block size for partial mode.</summary>
    public int? EncryptedBlockSize { get; }
}