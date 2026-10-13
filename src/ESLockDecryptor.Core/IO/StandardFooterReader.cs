using System.Buffers.Binary;
using System.IO.Hashing;
using ESLockDecryptor.Core.Models;

namespace ESLockDecryptor.Core.IO;

/// <summary>Reads a footer using its standard location and declared length.</summary>
public sealed class StandardFooterReader : IFooterReader
{
    /// <summary>Reads the standard footer while preserving the stream position.</summary>
    /// <param name="inputStream">A seekable encrypted input stream.</param>
    /// <returns>The parsed footer metadata.</returns>
    public EslockFooter ReadFooter(Stream inputStream)
    {
        ArgumentNullException.ThrowIfNull(inputStream);

        const int maxFooterSize = 1024;
        const int minFooterSize = 32;

        if (!inputStream.CanSeek)
            throw new NotSupportedException("Footer reading requires a seekable stream.");

        long originalPosition = inputStream.Position;
        try
        {
            long fileLength = inputStream.Length;
            ReadOnlySpan<byte> buffer = ReadStreamTail(inputStream, (int)Math.Min(fileLength, maxFooterSize));

            if (fileLength < minFooterSize)
            {
                throw new InvalidDataException("File is too small to be a valid .eslock file.");
            }

            int footerLength = BinaryPrimitives.ReadInt32BigEndian(buffer[^4..]);

            if (footerLength <= 0 || footerLength > maxFooterSize || footerLength >= fileLength)
            {
                throw new InvalidDataException("Incorrect footer length. "
                    + "Use the '--heuristic' option to try to find a valid footer.");
            }

            var footer = buffer[^footerLength..];

            uint storedCrc = (uint)BinaryPrimitives.ReadUInt64BigEndian(footer[^12..^4]);
            uint calculatedCrc = Crc32.HashToUInt32(footer[..^12]);

            var key = footer[^29..^13];

            int pos = 0; // Current position
            bool isPartialEncryption = footer[pos++] != 0xFF;
        
            int? encryptedBlockSize = null;

            if (isPartialEncryption)
            {
                encryptedBlockSize = BinaryPrimitives.ReadInt32BigEndian(footer[pos..(pos += 4)]);
            }

            int? originalNameLength = footer[pos++];
            ReadOnlySpan<byte> encryptedOriginalName;

            if (originalNameLength is not null && originalNameLength != 255)
            {
                if (pos + originalNameLength > footer.Length)
                {
                    throw new Exception("The encrypted name length is out of range of the footer. "
                        + "Try using the '--heuristic' option.");
                }
                encryptedOriginalName = footer[pos..(pos += (int)originalNameLength)];
            }
            else
            {
                originalNameLength = null;
                encryptedOriginalName = null;
            }

            return new EslockFooter
            {
                FooterOffset = fileLength - footerLength,
                IsParsedSuccessfully = true,
                RawData = footer.ToArray(),
                IsPartialEncryption = isPartialEncryption,
                EncryptedBlockSize = encryptedBlockSize,
                OriginalNameLength = originalNameLength,
                EncryptedOriginalName = encryptedOriginalName.ToArray(),
                StoredCrc = storedCrc,
                CalculatedCrc = calculatedCrc,
                Key = key.ToArray(),
                FooterLength = footerLength
            };
        }
        finally
        {
            inputStream.Position = originalPosition;
        }
    }

    private static ReadOnlySpan<byte> ReadStreamTail(Stream inputStream, int length)
    {
        var buffer = new byte[length];

        inputStream.Seek(-length, SeekOrigin.End);
        inputStream.ReadExactly(buffer);

        return new ReadOnlySpan<byte>(buffer);
    }
}