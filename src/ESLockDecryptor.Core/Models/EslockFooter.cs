namespace ESLockDecryptor.Core.Models;

/// <summary>Contains metadata parsed from an ESLock footer.</summary>
public sealed record EslockFooter
{
    private byte[] _rawData = [];
    private byte[]? _encryptedOriginalName;
    private byte[]? _key;

    /// <summary>Gets the absolute offset at which the footer begins.</summary>
    public required long FooterOffset { get; init; }
    /// <summary>Gets whether the footer structure was parsed successfully.</summary>
    public required bool IsParsedSuccessfully { get; init; }

    /// <summary>Gets a copy of the raw footer bytes.</summary>
    public byte[] RawData
    {
        get => [.. _rawData];
        init => _rawData = value?.ToArray() ?? [];
    }

    /// <summary>Gets whether the file uses partial encryption.</summary>
    public bool? IsPartialEncryption { get; init; }
    /// <summary>Gets the encrypted edge block size for partial encryption.</summary>
    public int? EncryptedBlockSize { get; init; }
    /// <summary>Gets the original file name length stored in the footer.</summary>
    public int? OriginalNameLength { get; init; }

    /// <summary>Gets a copy of the encrypted original file name.</summary>
    public byte[]? EncryptedOriginalName
    {
        get => _encryptedOriginalName?.ToArray();
        init => _encryptedOriginalName = value?.ToArray();
    }

    /// <summary>Gets the CRC value stored in the footer.</summary>
    public uint? StoredCrc { get; init; }
    /// <summary>Gets the CRC value calculated while parsing the footer.</summary>
    public uint? CalculatedCrc { get; init; }
    /// <summary>Gets whether the stored and calculated CRC values match.</summary>
    public bool IsCrcValid => StoredCrc is not null && StoredCrc == CalculatedCrc;

    /// <summary>Gets a copy of the AES key stored in the footer, if available.</summary>
    public byte[]? Key
    {
        get => _key?.ToArray();
        init => _key = value?.ToArray();
    }

    /// <summary>Gets the declared footer length.</summary>
    public int? FooterLength { get; init; }
}