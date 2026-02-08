namespace ESLockDecryptor.Configuration;

public record DecryptionConfig
{
    public required long OriginalFileLength;
    public required byte[] Key;
    public required bool IsPartialDecryption;
    public int? EncryptedBlockSize
    {
        get => IsPartialDecryption ? _encryptedBlockSize : null;
        init
        {
            if (value is not null)
            {
                if (!IsPartialDecryption)
                    throw new ArgumentException("Encrypted block size can be set only for partial decryption.");
                else if (value <= 0)
                    throw new ArgumentException("Encrypted block size must be greater than zero.");
                else
                    _encryptedBlockSize = value;
            }
            else
            {
                if (IsPartialDecryption)
                    _encryptedBlockSize = 1024;
                else
                    _encryptedBlockSize = value;
            }
        }
    }
    public bool IsFileTruncated = false;

    private int? _encryptedBlockSize;
}