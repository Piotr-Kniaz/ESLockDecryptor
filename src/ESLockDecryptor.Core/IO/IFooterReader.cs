using ESLockDecryptor.Core.Models;

namespace ESLockDecryptor.Core.IO;

/// <summary>Reads ESLock metadata from an encrypted stream.</summary>
public interface IFooterReader
{
    /// <summary>Reads the footer while preserving the stream position.</summary>
    /// <param name="inputStream">A seekable encrypted input stream.</param>
    /// <returns>The parsed footer metadata.</returns>
    EslockFooter ReadFooter(Stream inputStream);
}