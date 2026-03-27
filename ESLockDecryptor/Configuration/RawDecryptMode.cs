namespace ESLockDecryptor.Configuration;

public sealed record RawDecryptMode(
    string Name,
    bool? IsPartialProvided)
{
    public static readonly RawDecryptMode Undefined = new(nameof(Undefined), null);
    public static readonly RawDecryptMode Auto = new(nameof(Auto), null);
    public static readonly RawDecryptMode Full = new(nameof(Full), false);
    public static readonly RawDecryptMode Partial = new(nameof(Partial), true);

    public static readonly IReadOnlyCollection<RawDecryptMode> All =
    [
        Auto,
        Full,
        Partial
    ];

    public static RawDecryptMode FromName(string? name) =>
        All.FirstOrDefault(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) ?? Undefined;
}