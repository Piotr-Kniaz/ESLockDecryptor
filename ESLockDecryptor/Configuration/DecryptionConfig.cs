namespace ESLockDecryptor.Configuration;

public record DecryptionConfig
{
    public byte[] Key { get; init; } = [];
    public bool IsPartialDecryption { get; init; }
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
    public long? FooterStartPosition
    {
        get => _footerStartPosition;
        init => _footerStartPosition =
            (value >= 0 && value is not null) || value is null
                ? value
                : throw new ArgumentException("Footer start position must be non-negative.");
    }

    private int? _encryptedBlockSize;
    private long? _footerStartPosition;
}