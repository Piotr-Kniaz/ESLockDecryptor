using System.Buffers.Binary;
using System.IO.Hashing;
using ESLockDecryptor.Interfaces;
using ESLockDecryptor.Models;

namespace ESLockDecryptor.IO;

public class StandardFooterReader : IFooterReader
{
    public EslockFooter ReadFooter(string filePath)
    {
        const int maxFooterSize = 1024;
        const int minFooterSize = 29;
        long fileLength;
        Span<byte> buffer = [];

        using (var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
        {
            fileLength = fileStream.Length;
            int bytesToRead = (int)Math.Min(fileLength, maxFooterSize);
            fileStream.Seek(-bytesToRead, SeekOrigin.End);
            fileStream.ReadExactly(buffer);
        }

        if (fileLength < minFooterSize)
        {
            throw new InvalidDataException("File is too small to be a valid .eslock file.");
        }

        int footerLength = BinaryPrimitives.ReadInt32BigEndian(buffer[^4..]);

        if (footerLength <= 0 || footerLength > maxFooterSize || footerLength >= fileLength)
        {
            throw new InvalidDataException("Incorrect footer length.");
        }

        var footer = buffer[^footerLength..];

        uint storedCrc = (uint)BinaryPrimitives.ReadUInt64BigEndian(footer[^12..^4]);
        uint calculatedCrc = Crc32.HashToUInt32(footer[..^12]);

        var key = footer[^29..^13];

        int currentPos = 0;
        bool isPartialEncryption = footer[currentPos++] != 0xFF;
        
        int encryptedBlockSize = 0;

        if (isPartialEncryption)
        {
            encryptedBlockSize = BinaryPrimitives.ReadInt32BigEndian(footer[currentPos..(currentPos + 4)]);
            currentPos += 4;
        }

        int originalNameLength = footer[currentPos++];
        var encryptedOriginalName = new ReadOnlySpan<byte>();

        if (originalNameLength != -1 && originalNameLength != 255)
        {
            int normalizedNameLen = ((originalNameLength - 1 >> 4) + 1) << 4;
            encryptedOriginalName = footer[currentPos..(currentPos + normalizedNameLen)];
            // currentPos += normalizedNameLen;
        }

        return new EslockFooter
        {
            RawData = footer.ToArray(),
            IsPartialEncryption = isPartialEncryption,
            EncryptedBlockSize = encryptedBlockSize,
            OriginalNameLength = originalNameLength,
            EncryptedOriginalName = encryptedOriginalName.ToArray(),
            StoredCrc = storedCrc,
            CalculatedCrc = calculatedCrc,
            IsCrcValid = storedCrc == calculatedCrc,
            Key = key.ToArray(),
            FooterLength = footerLength
        };
    }
}