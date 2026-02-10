using System.Buffers.Binary;
using System.IO.Hashing;
using ESLockDecryptor.Models;

namespace ESLockDecryptor.IO;

public class StandardFooterReader : IFooterReader
{
    public EslockFooter ReadFooter(string filePath)
    {
        const int maxFooterSize = 1024;
        const int minFooterSize = 29;

        long fileLength = new FileInfo(filePath).Length;

        ReadOnlySpan<byte> buffer = ReadFileTail(filePath, (int)Math.Min(fileLength, maxFooterSize));

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

        int currentPos = 0;
        bool isPartialEncryption = footer[currentPos++] != 0xFF;
        
        int? encryptedBlockSize = null;

        if (isPartialEncryption)
        {
            encryptedBlockSize = BinaryPrimitives.ReadInt32BigEndian(footer[currentPos..(currentPos + 4)]);
            currentPos += 4;
        }

        int? originalNameLength = footer[currentPos++];
        ReadOnlySpan<byte> encryptedOriginalName;

        if (originalNameLength != 255)
        {
            int normalizedNameLen = (((int)originalNameLength - 1 >> 4) + 1) << 4;
            if (currentPos + normalizedNameLen > footer.Length)
            {
                throw new Exception("The encrypted name length is out of range of the footer. "
                    + "Try using the '--heuristic' option.");
            }
            encryptedOriginalName = footer[currentPos..(currentPos + normalizedNameLen)];
            // currentPos += normalizedNameLen;
        }
        else
        {
            originalNameLength = null;
            encryptedOriginalName = null;
        }

        return new EslockFooter
        {
            StartFooterPosition = fileLength - footerLength,
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

    private ReadOnlySpan<byte> ReadFileTail(string filePath, int length)
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