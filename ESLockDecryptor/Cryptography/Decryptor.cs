using System.Security.Cryptography;
using System.Text;
using ESLockDecryptor.Configuration;
using ESLockDecryptor.Extensions;

namespace ESLockDecryptor.Cryptography;

public static class Decryptor
{
    public static void DecryptStream(Stream inputStream, Stream outputStream, DecryptionConfig config)
    {
        using var aes = CreateAes(config.Key);

        long originalFileLength = config.OriginalFileLength;

        if (config.IsPartialEncryption)
        {
            int firstBlockLength = config.EncryptedBlockSize ?? 1024;
            int lastBlockLength = config.IsFileTruncated ? 0 : firstBlockLength;
            long middlePartLength = originalFileLength - (firstBlockLength + lastBlockLength);

            if (firstBlockLength + lastBlockLength > originalFileLength)
            {
                throw new InvalidOperationException("Encrypted blocks are larger than the file length.");
            }

            var buffer = new byte[firstBlockLength];
            inputStream.ReadExactly(buffer, 0, buffer.Length);
            byte[] decryptedFirstBlock;
            using (var decryptor = aes.CreateDecryptor())
            {
                decryptedFirstBlock = decryptor.TransformFinalBlock(buffer, 0, buffer.Length);
            }
            outputStream.Write(decryptedFirstBlock, 0, decryptedFirstBlock.Length);

            if (middlePartLength > 0)
            {
                inputStream.CopyTo(outputStream, count: middlePartLength);
            }

            if (lastBlockLength > 0)
            {
                inputStream.ReadExactly(buffer, 0, buffer.Length);
                byte[] decryptedLastBytes;
                using (var decryptor = aes.CreateDecryptor())
                {
                    decryptedLastBytes = decryptor.TransformFinalBlock(buffer, 0, buffer.Length);
                }
                outputStream.Write(decryptedLastBytes, 0, decryptedLastBytes.Length);
            }
        }
        else
        {
            using var decryptor = aes.CreateDecryptor();
            using var cryptoStream = new CryptoStream(inputStream, decryptor, CryptoStreamMode.Read);
            cryptoStream.CopyTo(outputStream, count: originalFileLength);
        }
    }

    public static string DecryptFileName(byte[] encryptedName, byte[] key, int nameLength)
    {
        using var aes = CreateAes(key);
        using var decryptor = aes.CreateDecryptor();

        var decryptedNameBytes = decryptor.TransformFinalBlock(encryptedName, 0, encryptedName.Length);

        return Encoding.UTF8.GetString(decryptedNameBytes, 0, nameLength);
    }

    private static Aes CreateAes(byte[] key)
    {
        var aes = Aes.Create();
        aes.Key = key;
        aes.IV = IV;
        aes.Mode = CipherMode.CFB;
        aes.Padding = PaddingMode.None;
        aes.FeedbackSize = 128;
        return aes;
    }

    private static byte[] IV { get; } = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
}