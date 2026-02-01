namespace ESLockDecryptor.Models;

public record EslockFooter
{
    public byte[] RawData { get; init; } = [];
    public bool IsPartialEncryption { get; init; }
    public int EncryptedBlockSize { get; init; }
    public int OriginalNameLength { get; init; }
    public byte[] EncryptedOriginalName { get; init; } = [];
    public uint StoredCrc { get; init; }
    public uint CalculatedCrc { get; init; }
    public bool IsCrcValid { get; init; }
    public byte[] Key { get; init; } = [];
    public int FooterLength { get; init; }
}