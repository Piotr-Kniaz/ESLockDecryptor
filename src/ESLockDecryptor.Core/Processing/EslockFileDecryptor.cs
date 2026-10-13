using ESLockDecryptor.Core.Configuration;
using ESLockDecryptor.Core.Cryptography;
using ESLockDecryptor.Core.IO;
using ESLockDecryptor.Core.Models;

namespace ESLockDecryptor.Core.Processing;

/// <summary>Provides the high-level workflow for reading and decrypting one ESLock stream.</summary>
public static class EslockFileDecryptor
{
    /// <summary>Reads footer metadata from a seekable input stream.</summary>
    /// <param name="input">The encrypted input stream.</param>
    /// <param name="heuristic">Whether heuristic footer detection should be used.</param>
    /// <returns>The parsed footer metadata.</returns>
    public static EslockFooter ReadFooter(Stream input, bool heuristic = false)
    {
        ArgumentNullException.ThrowIfNull(input);

        if (!input.CanSeek)
            throw new NotSupportedException("Footer reading requires a seekable stream.");

        input.Position = 0;
        IFooterReader footerReader = heuristic
            ? new HeuristicFooterReader()
            : new StandardFooterReader();

        return footerReader.ReadFooter(input);
    }

    /// <summary>Builds a decryption plan without writing decrypted output.</summary>
    /// <param name="input">The seekable encrypted input stream.</param>
    /// <param name="options">Options controlling footer parsing and key selection.</param>
    /// <returns>A validated decryption plan.</returns>
    public static DecryptionPlan Prepare(Stream input, DecryptionOptions options)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(options);

        if (!input.CanSeek)
            throw new NotSupportedException("Decryption requires a seekable input stream.");

        input.Position = 0;

        EslockFooter? footer = null;
        if (options.RawDecrypt is null || options.Heuristic)
        {
            footer = ReadFooter(input, options.Heuristic);

            if (!footer.IsCrcValid && !options.IgnoreCrc)
                throw new InvalidDataException("CRC check failed. Use IgnoreCrc to bypass this check.");
        }

        byte[] key = GetKey(options, footer);
        DecryptionConfig configuration = CreateConfiguration(input.Length, footer, options, key);

        string? originalFileName = footer?.EncryptedOriginalName is not null && footer.OriginalNameLength is not null
            ? EslockDecryptor.DecryptFileName(footer.EncryptedOriginalName, key)
            : null;

        return new DecryptionPlan(configuration, footer, originalFileName);
    }

    /// <summary>Decrypts the input stream according to a previously prepared plan.</summary>
    /// <param name="input">The seekable encrypted input stream.</param>
    /// <param name="output">The destination stream.</param>
    /// <param name="plan">The plan returned by <see cref="Prepare"/>.</param>
    public static void Decrypt(Stream input, Stream output, DecryptionPlan plan)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(plan);

        if (!input.CanSeek)
            throw new NotSupportedException("Decryption requires a seekable input stream.");

        input.Position = 0;
        EslockDecryptor.DecryptStream(input, output, plan.Configuration);
    }

    private static DecryptionConfig CreateConfiguration(
        long fileLength,
        EslockFooter? footer,
        DecryptionOptions options,
        byte[] key)
    {
        const bool isPartialDefault = true;
        const int encryptedBlockDefault = 1024;

        if (options.RawDecrypt is not null)
        {
            bool isPartial = options.RawDecrypt.Mode.IsPartialProvided
                ?? footer?.IsPartialEncryption
                ?? isPartialDefault;

            return isPartial
                ? DecryptionConfig.CreatePartialEncryption(
                    originalFileLength: footer?.FooterOffset ?? fileLength,
                    key: key,
                    encryptedBlockSize: options.RawDecrypt.EncryptedBlockSize
                        ?? footer?.EncryptedBlockSize
                        ?? encryptedBlockDefault,
                    isFileTruncated: footer is null)
                : DecryptionConfig.CreateFullEncryption(
                    originalFileLength: footer?.FooterOffset ?? fileLength,
                    key: key,
                    isFileTruncated: footer is null);
        }

        if (footer is null)
            throw new InvalidDataException("Footer is required for standard decryption.");

        return footer.IsPartialEncryption ?? isPartialDefault
            ? DecryptionConfig.CreatePartialEncryption(
                originalFileLength: footer.FooterOffset,
                key: key,
                encryptedBlockSize: footer.EncryptedBlockSize ?? encryptedBlockDefault)
            : DecryptionConfig.CreateFullEncryption(
                originalFileLength: footer.FooterOffset,
                key: key);
    }

    private static byte[] GetKey(DecryptionOptions options, EslockFooter? footer)
    {
        if (options.Key is not null)
            return [.. options.Key];

        if (options.Password is not null)
            return KeyDerivator.DeriveKeyFromPassword(options.Password);

        if (footer?.Key?.Length == 16)
            return footer.Key;

        throw new InvalidDataException("Key for decryption not found or corrupted.");
    }
}