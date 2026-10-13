using System.Buffers.Binary;
using System.IO.Hashing;
using ESLockDecryptor.Core.Models;

namespace ESLockDecryptor.Core.IO;

/// <summary>Searches the end of a damaged file for plausible footer metadata.</summary>
public sealed class HeuristicFooterReader : IFooterReader
{
    private const int SearchWindiwSize = 128 * 1024;
    private static readonly byte[][] Signatures = 
    [
        [0x04, 0x00, 0x00, 0x04, 0x00], // partial encryption - most cases
        [0x04, 0x00, 0x02, 0x08, 0x00]  // partial encryption - mp3 files
    ];

    /// <summary>Searches for and reads a plausible footer while preserving the stream position.</summary>
    /// <param name="inputStream">A seekable encrypted input stream.</param>
    /// <returns>The best matching footer metadata.</returns>
    public EslockFooter ReadFooter(Stream inputStream)
    {
        ArgumentNullException.ThrowIfNull(inputStream);

        if (!inputStream.CanSeek)
            throw new NotSupportedException("Footer reading requires a seekable stream.");

        long originalPosition = inputStream.Position;
        try
        {
            long fileLength = inputStream.Length;
            int bufferSize = (int)Math.Min(fileLength, SearchWindiwSize);
            var buffer = ReadStreamTail(inputStream, bufferSize);

            var candidates = FindCandidatesBySignature(buffer, fileLength);
            candidates.AddRange(FindCandidatesByStructure(buffer, fileLength));

            var footer = candidates
                .OrderByDescending(c => c.IsCrcValid)
                .ThenByDescending(c => c.IsParsedSuccessfully)
                .ThenByDescending(c => c.FooterOffset)
                .FirstOrDefault();

            return footer
                ?? throw new InvalidDataException("Footer not found. Extract key from the valid file and try '--raw-decrypt' option.");
        }
        finally
        {
            inputStream.Position = originalPosition;
        }
    }

    private static List<EslockFooter> FindCandidatesBySignature(ReadOnlySpan<byte> buffer, long totalFileLength)
    {
        var candidates = new List<EslockFooter>();
        foreach (var signature in Signatures)
        {
            var candidateOffsets = FindSignature(buffer, signature);

            foreach (var offset in candidateOffsets)
            {
                candidates.Add(SequentialParseFooter(buffer, totalFileLength, offset));
            }
        }
        return candidates;
    }

    private static List<EslockFooter> FindCandidatesByStructure(ReadOnlySpan<byte> buffer, long totalFileLength)
    {
        const int maxFooterSize = 1024;
        const int minFooterSize = 32;

        var candidates = new List<EslockFooter>();

        for (int i = buffer.Length - 22; i >= 0; i--)
        {
            if (buffer[i] != 0x10) continue; // Key prefix Magic
            if (buffer[i + 17] != 0x00 && buffer[i + 17] != 0x02) continue; // Key postfix Magics
            if (!buffer[(i + 1)..(i + 17)].ContainsAnyExcept((byte)0x00)) continue; // Key cannot consist of only 0x00
            if (buffer[(i + 18)..(i + 22)].ContainsAnyExcept((byte)0x00)) continue; // Padding before CRC

            if (i - 2 >= 0 && !buffer[(i - 2)..i].ContainsAnyExcept((byte)0xFF))
            {
                var candidate = SequentialParseFooter(buffer, totalFileLength, i - 2);
                if (candidate.IsCrcValid || candidate.RawData.Length == candidate.FooterLength)
                {
                    candidates.Add(candidate);
                    continue;
                }
            }
            if (i + 30 <= buffer.Length)
            {
                int declaredLength = BinaryPrimitives.ReadInt32BigEndian(buffer[(i + 26)..(i + 30)]);
                if (declaredLength > maxFooterSize || declaredLength < minFooterSize) continue;
                var candidate = SequentialParseFooter(buffer, totalFileLength, i + 30 - declaredLength);
                if (candidate.IsCrcValid) candidates.Add(candidate);
            }
        }

        return candidates;
    }

    private static List<int> FindSignature(ReadOnlySpan<byte> buffer, byte[] signature)
    {
        var positions = new List<int>();
        for (int i = buffer.Length - signature.Length; i >= 0; i--)
        {
            bool match = true;
            for (int j = 0; j < signature.Length; j++)
            {
                if (buffer[i + j] != signature[j])
                {
                    match = false;
                    break;
                }
            }
            if (match) positions.Add(i);
        }
        return positions;
    }

    private static EslockFooter SequentialParseFooter(ReadOnlySpan<byte> buffer, long totalFileLength, int offset)
    {
        int pos = offset; // Current position

        bool? isPatrialEncryption = null;
        int? encryptedBlockSize = null;
        int? originalNameLength = null;
        var encryptedOriginalName = new ReadOnlySpan<byte>();
        uint? storedCrc = null;
        uint? calculatedCrc = null;
        var key = new ReadOnlySpan<byte>();
        int? footerLength = null;

        bool isStructureValid = true;
        bool isTruncated = false;

        try
        {
            isPatrialEncryption = buffer[pos++] != 0xFF;
            if ((bool)isPatrialEncryption)
            {
                encryptedBlockSize = BinaryPrimitives.ReadInt32BigEndian(buffer[pos..(pos += 4)]);
            }

            originalNameLength = buffer[pos++];
            if (originalNameLength is not null && originalNameLength != 255)
            {
                encryptedOriginalName = buffer[pos..(pos += (int)originalNameLength)];
            }

            isStructureValid = buffer[pos++] == 0x10;
            key = buffer[pos..(pos += 16)];
            isStructureValid &= buffer[pos] == 0x00 || buffer[pos] == 0x02;
            pos++;

            calculatedCrc = Crc32.HashToUInt32(buffer[offset..pos]);

            isStructureValid &= !buffer[pos..(pos + 4)].ContainsAnyExcept((byte)0x00);
            pos += 4;

            storedCrc = BinaryPrimitives.ReadUInt32BigEndian(buffer[pos..(pos += 4)]);
            footerLength = BinaryPrimitives.ReadInt32BigEndian(buffer[pos..(pos += 4)]);
                    
            isStructureValid &= (pos - footerLength) == offset;
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException || ex is IndexOutOfRangeException)
        {
            isTruncated = true;
        }

        return new EslockFooter
        {
            FooterOffset = totalFileLength - buffer.Length + offset,
            IsParsedSuccessfully = isStructureValid && !isTruncated,
            RawData = buffer[offset..(isTruncated ? buffer.Length : pos)].ToArray(),
            IsPartialEncryption = isPatrialEncryption,
            EncryptedBlockSize = encryptedBlockSize,
            OriginalNameLength = originalNameLength,
            EncryptedOriginalName = encryptedOriginalName.Length > 0 ? encryptedOriginalName.ToArray() : null,
            StoredCrc = storedCrc,
            CalculatedCrc = calculatedCrc,
            Key = key.Length > 0 ? key.ToArray() : null,
            FooterLength = footerLength
        };
    }

    private static ReadOnlySpan<byte> ReadStreamTail(Stream inputStream, int length)
    {
        var buffer = new byte[length];

        inputStream.Seek(-length, SeekOrigin.End);
        inputStream.ReadExactly(buffer);

        return new ReadOnlySpan<byte>(buffer);
    }
}