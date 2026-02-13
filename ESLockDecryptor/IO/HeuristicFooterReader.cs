using System.Buffers.Binary;
using System.IO.Hashing;
using ESLockDecryptor.Models;

namespace ESLockDecryptor.IO;

public class HeuristicFooterReader : IFooterReader
{
    private const int SearchWindiwSize = 128 * 1024;
    private const int MinFooterSize = 29;
    private static readonly byte[][] Signatures = 
    [
        [0x04, 0x00, 0x00, 0x04, 0x00], // partial encryption - most cases
        [0x04, 0x00, 0x02, 0x08, 0x00]  // partial encryption - mp3 files
    ];
    private const byte KeyPrefixMagic = 0x10;
    private const byte KeyPostfixMagic = 0x00;
    private readonly List<EslockFooter> FooterCandidates = [];

    public EslockFooter ReadFooter(string filePath)
    {
        long fileLength = new FileInfo(filePath).Length;

        int bufferSize = (int)Math.Min(fileLength, SearchWindiwSize);

        var buffer = ReadFileTail(filePath, bufferSize);

        var candidates = FindFooterBySignature(buffer, fileLength);

        if (candidates.Count > 0) return candidates[0];

        throw new InvalidDataException("Heuristic scan failed.");
    }

    private static List<EslockFooter> FindFooterBySignature(ReadOnlySpan<byte> buffer, long totalFileLength)
    {
        var candidates = new List<EslockFooter>();
        foreach (var signature in Signatures)
        {
            var candidateOffsets = FindSignature(buffer, signature);

            foreach (var offset in candidateOffsets)
            {
                int pos = offset; // Current position
                // bool isParsedSuccessfully = true;

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
                        encryptedBlockSize = BinaryPrimitives.ReadInt32BigEndian(buffer[pos..(pos + 4)]);
                        pos += 4;
                    }

                    originalNameLength = buffer[pos++];
                    if (originalNameLength != 255)
                    {
                        int normalizedNameLen = (((int)originalNameLength - 1 >> 4) + 1) << 4;
                        encryptedOriginalName = buffer[pos..(pos + normalizedNameLen)];
                        pos += normalizedNameLen;
                    }

                    isStructureValid = buffer[pos++] == KeyPrefixMagic;
                    key = buffer[pos..(pos + 16)];
                    pos += 16;
                    isStructureValid = isStructureValid && buffer[pos++] == KeyPostfixMagic;

                    calculatedCrc = Crc32.HashToUInt32(buffer[offset..pos]);

                    for (int i = 0; i < 4; i++)
                    {
                        isStructureValid = isStructureValid && buffer[pos++] == 0x00;
                    }

                    storedCrc = (uint)BinaryPrimitives.ReadUInt32BigEndian(buffer[pos..(pos + 4)]);
                    pos += 4;
                    footerLength = BinaryPrimitives.ReadInt32BigEndian(buffer[pos..(pos + 4)]);
                    pos += 4;
                    
                    isStructureValid = isStructureValid && pos - footerLength == offset;
                }
                catch (Exception ex) when (ex is ArgumentOutOfRangeException || ex is IndexOutOfRangeException)
                {
                    isTruncated = true;
                }

                candidates.Add(new EslockFooter
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
                });
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

    private static ReadOnlySpan<byte> ReadFileTail(string filePath, int length)
    {
        var buffer = new byte[length];
        
        using var fileStream = new FileStream(
            path: filePath,
            mode: FileMode.Open,
            access: FileAccess.Read,
            share: FileShare.Read,
            bufferSize: 1,
            options: FileOptions.RandomAccess);

        fileStream.Seek(-length, SeekOrigin.End);
        fileStream.ReadExactly(buffer);

        return new ReadOnlySpan<byte>(buffer);
    }
}