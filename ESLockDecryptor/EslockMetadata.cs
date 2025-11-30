using System.Security.Cryptography;
using System.IO.Hashing;
using System.Buffers.Binary;
using System.Text;

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
        fs.ReadExactly(footerLengthBytes);
        int footerLength = BinaryPrimitives.ReadInt32BigEndian(footerLengthBytes);

        if (footerLength <= 0 || footerLength > 1024 || footerLength >= fileLength)
        {
            Console.WriteLine("[WARNING] Incorrect footer length. File is corrupted or is not an .eslock file.");
            return null;
        }

        fs.Seek(-12, SeekOrigin.End);
        var storedCrcBytes = new byte[8];
        fs.ReadExactly(storedCrcBytes);
        uint storedCrc = (uint)BinaryPrimitives.ReadInt64BigEndian(storedCrcBytes);

        int footerDataLength = footerLength - 12;
        fs.Seek(-(footerLength - 4), SeekOrigin.Current);
        var footerDataBytes = new byte[footerDataLength];
        fs.ReadExactly(footerDataBytes);

        var calculatedCrc = Crc32.HashToUInt32(footerDataBytes);

        if (storedCrc != calculatedCrc)
        {
            Console.WriteLine("[WARNING] CRC check error. File may be corrupted.");
            return null;
        }

        fs.Seek(-29, SeekOrigin.End);
        var key = new byte[16];
        fs.ReadExactly(key);

        using var footerStream = new MemoryStream(footerDataBytes);
        using var reader = new BinaryReader(footerStream);

        bool isPartial = reader.ReadByte() != 0xFF;
        int encryptedLength = 0;

        if (isPartial)
        {
            var lenBytes = reader.ReadBytes(4);
            encryptedLength = BinaryPrimitives.ReadInt32BigEndian(lenBytes);
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

            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = IV;
            aes.Mode = CipherMode.CFB;
            aes.Padding = PaddingMode.None;
            aes.FeedbackSize = 128;

            using var decryptor = aes.CreateDecryptor();

            var decryptedNameBytes = decryptor.TransformFinalBlock(encryptedFileNameBytes, 0, encryptedFileNameBytes.Length);

            originalFileName = Encoding.UTF8.GetString(decryptedNameBytes, 0, fileNameLength);
        }

        return new EslockMetadata(key, footerLength, originalFileName, isPartial, encryptedLength);
    }
}