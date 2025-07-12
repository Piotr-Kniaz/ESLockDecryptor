using System.IO.Hashing;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace ESLockDecryptor;

public class EslockMetadata
{
    public byte[] Key { get; }
    public static byte[] IV { get; } = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    public int FooterLength { get; }
    public string OriginalFileName { get; }
    public bool IsPartial { get; }
    public int EncryptedLength { get; }

    private EslockMetadata(byte[] key, int footerLength, string originalFileName, bool isPartial, int encryptedLength)
    {
        Key = key;
        FooterLength = footerLength;
        OriginalFileName = originalFileName;
        IsPartial = isPartial;
        EncryptedLength = encryptedLength;
    }

    public static EslockMetadata? Parse(string eslockFilePath)
    {
        using var fs = new FileStream(eslockFilePath, FileMode.Open, FileAccess.Read);
        long fileLength = fs.Length;

        if (fileLength < 29) return null;

        fs.Seek(-4, SeekOrigin.End);
        var footerLengthBytes = new byte[4];
        fs.ReadExactly(footerLengthBytes, 0, 4);
        int footerLength = ReadBigEndianInt32(footerLengthBytes, 0);

        if (footerLength <= 0 || footerLength > 1024 || footerLength >= fileLength)
        {
            Console.WriteLine("[WARNING] Incorrect footer length. File is corrupted or is not an .eslock file.");
            return null;
        }

        fs.Seek(-12, SeekOrigin.End);
        var storedCrcBytes = new byte[8];
        fs.ReadExactly(storedCrcBytes, 0, 8);
        uint storedCrc = (uint)ReadBigEndianInt64(storedCrcBytes, 0);

        int footerDataLength = footerLength - 12;
        fs.Seek(-(footerLength - 4), SeekOrigin.Current);
        var footerDataBytes = new byte[footerDataLength];
        fs.ReadExactly(footerDataBytes, 0, footerDataLength);

        var calculatedCrc = Crc32.HashToUInt32(footerDataBytes);

        if (storedCrc != calculatedCrc)
        {
            Console.WriteLine("[WARNING] CRC check error. File may be corrupted.");
            return null;
        }

        fs.Seek(-29, SeekOrigin.End);
        var key = new byte[16];
        fs.ReadExactly(key, 0, 16);

        using var footerStream = new MemoryStream(footerDataBytes);
        using var reader = new BinaryReader(footerStream);

        bool isPartial = reader.ReadByte() != 0xFF;
        int encryptedLength = 0;
        if (isPartial)
        {
            var lenBytes = reader.ReadBytes(4);
            encryptedLength = ReadBigEndianInt32(lenBytes, 0);
        }

        int fileNameLength = reader.ReadByte();
        string originalFileName;

        if (fileNameLength == -1 || fileNameLength == 255)
        {
            originalFileName = Path.GetFileNameWithoutExtension(eslockFilePath);
        }
        else
        {
            int normalizedLen = ((fileNameLength - 1 >> 4) + 1) << 4;
            var encryptedFileNameBytes = reader.ReadBytes(normalizedLen);

            var cipher = CipherUtilities.GetCipher("AES/CFB/NoPadding");
            var keyParam = new KeyParameter(key);
            var ivParam = new ParametersWithIV(keyParam, IV);
            cipher.Init(false, ivParam);
            var decryptedNameBytes = cipher.DoFinal(encryptedFileNameBytes);
            originalFileName = Encoding.UTF8.GetString(decryptedNameBytes, 0, fileNameLength);
        }

        return new EslockMetadata(key, footerLength, originalFileName, isPartial, encryptedLength);
    }

    private static int ReadBigEndianInt32(byte[] data, int offset)
    {
        Array.Reverse(data, offset, 4);
        return BitConverter.ToInt32(data, offset);
    }

    private static long ReadBigEndianInt64(byte[] data, int offset)
    {
        Array.Reverse(data, offset, 8);
        return BitConverter.ToInt64(data, offset);
    }
}