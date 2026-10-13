namespace ESLockDecryptor.Core.Configuration;

/// <summary>Identifies how raw decryption interprets encrypted content.</summary>
public sealed record RawDecryptMode(
    string Name,
    bool? IsPartialProvided)
{
    /// <summary>Represents an unknown mode.</summary>
    public static readonly RawDecryptMode Undefined = new(nameof(Undefined), null);
    /// <summary>Automatically selects the encryption layout.</summary>
    public static readonly RawDecryptMode Auto = new(nameof(Auto), null);
    /// <summary>Indicates full encryption.</summary>
    public static readonly RawDecryptMode Full = new(nameof(Full), false);
    /// <summary>Indicates partial encryption.</summary>
    public static readonly RawDecryptMode Partial = new(nameof(Partial), true);

    /// <summary>Gets all supported raw decryption modes.</summary>
    public static IReadOnlyList<RawDecryptMode> All { get; } =
    [
        Auto,
        Full,
        Partial
    ];

    /// <summary>Finds a mode by name, or returns <see cref="Undefined"/> if not found.</summary>
    /// <param name="name">The mode name to find.</param>
    public static RawDecryptMode FromName(string? name) =>
        All.FirstOrDefault(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) ?? Undefined;
}