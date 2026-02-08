namespace ESLockDecryptor.Models;

public record EslockFooter
{
    public required long StartFooterPosition;
    public required bool IsParsedSuccessfully;
    public byte[] RawData = [];
    public bool? IsPartialEncryption;
    public int? EncryptedBlockSize;
    public int? OriginalNameLength;
    public byte[]? EncryptedOriginalName;
    public uint? StoredCrc;
    public uint? CalculatedCrc;
    public bool IsCrcValid { get => StoredCrc is not null && StoredCrc == CalculatedCrc; }
    public byte[]? Key = [];
    public int? FooterLength;
}