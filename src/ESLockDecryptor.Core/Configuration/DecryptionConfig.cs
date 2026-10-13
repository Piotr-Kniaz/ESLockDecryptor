namespace ESLockDecryptor.Core.Configuration;

/// <summary>Describes the encryption layout and key required to decrypt a stream.</summary>
public sealed record DecryptionConfig
{
    private byte[] _key = [];

    /// <summary>Gets the original content length, excluding the footer.</summary>
    public long OriginalFileLength { get; private init; }
    /// <summary>Gets a copy of the 16-byte AES key.</summary>
    public byte[] Key
    {
        get => [.. _key];
        private init => _key = value?.ToArray() ?? [];
    }

    /// <summary>Gets whether only the beginning and end are encrypted.</summary>
    public bool IsPartialEncryption { get; private init; }
    /// <summary>Gets the encrypted edge block size for partial encryption.</summary>
    public int? EncryptedBlockSize { get; private init; }
    /// <summary>Gets whether the encrypted input is truncated.</summary>
    public bool IsFileTruncated { get; private init; }

    /// <summary>Creates a configuration for fully encrypted content.</summary>
    /// <param name="originalFileLength">Original content length.</param>
    /// <param name="key">The 16-byte AES key.</param>
    /// <param name="isFileTruncated">Whether the encrypted input is truncated.</param>
    public static DecryptionConfig CreateFullEncryption(
        long originalFileLength,
        byte[] key,
        bool isFileTruncated = false)
    {
        ArgumentNullException.ThrowIfNull(key);

        if (key.Length != 16)
            throw new ArgumentException("Invalid key.", nameof(key));
        
        return new DecryptionConfig
        {
            OriginalFileLength = originalFileLength,
            Key = key,
            IsPartialEncryption = false,
            EncryptedBlockSize = null,
            IsFileTruncated = isFileTruncated
        };
    }

    /// <summary>Creates a configuration for partially encrypted content.</summary>
    /// <param name="originalFileLength">Original content length.</param>
    /// <param name="key">The 16-byte AES key.</param>
    /// <param name="encryptedBlockSize">Size of each encrypted edge block.</param>
    /// <param name="isFileTruncated">Whether the encrypted input is truncated.</param>
    public static DecryptionConfig CreatePartialEncryption(
        long originalFileLength,
        byte[] key,
        int encryptedBlockSize = 1024,
        bool isFileTruncated = false)
    {
        ArgumentNullException.ThrowIfNull(key);

        if (key.Length != 16)
            throw new ArgumentException("Invalid key.", nameof(key));
        if (encryptedBlockSize > originalFileLength || encryptedBlockSize <= 0)
            throw new ArgumentException("Invalid EncryptedBlockSize.", nameof(encryptedBlockSize));
        
        return new DecryptionConfig
        {
            OriginalFileLength = originalFileLength,
            Key = key,
            IsPartialEncryption = true,
            EncryptedBlockSize = encryptedBlockSize,
            IsFileTruncated = isFileTruncated
        };
    }

    private DecryptionConfig() { }
}