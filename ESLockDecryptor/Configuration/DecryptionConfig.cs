namespace ESLockDecryptor.Configuration;

public record DecryptionConfig
{
    public long OriginalFileLength { get; private init; }
    public byte[] Key { get; private init; } = [];
    public bool IsPartialEncryption { get; private init; }
    public int? EncryptedBlockSize { get; private init; }
    public bool IsFileTruncated { get; private init; }

    public static DecryptionConfig CreateFullEncrypt(long originalFileLength, byte[] key, bool isFileTruncated = false)
    {
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

    public static DecryptionConfig CreatePartialEncrypt(long originalFileLength, byte[] key,
        int encryptedBlockSize = 1024, bool isFileTruncated = false)
    {
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