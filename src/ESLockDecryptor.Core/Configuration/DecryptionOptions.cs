namespace ESLockDecryptor.Core.Configuration;

/// <summary>Specifies how an ESLock stream should be prepared for decryption.</summary>
public sealed record DecryptionOptions
{
    /// <summary>Gets or sets an explicit 16-byte AES key.</summary>
    public byte[]? Key { get; init; }
    /// <summary>Gets or sets a password from which the AES key is derived.</summary>
    public string? Password { get; init; }
    /// <summary>Gets or sets whether footer CRC errors are ignored.</summary>
    public bool IgnoreCrc { get; init; }
    /// <summary>Gets or sets whether heuristic footer detection is used.</summary>
    public bool Heuristic { get; init; }
    /// <summary>Gets or sets raw decryption settings.</summary>
    public RawDecryptConfig? RawDecrypt { get; init; }
}