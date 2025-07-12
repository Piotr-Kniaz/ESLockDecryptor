using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace ESLockDecryptor;

public static class EslockDecryptor
{
    public static void DecryptFile(string eslockFilePath, string outputFilePath)
    {
        Console.WriteLine($"Start of decryption: {Path.GetFileName(eslockFilePath)}");
        try
        {
            var metadata = EslockMetadata.Parse(eslockFilePath);
            if (metadata == null)
            {
                Console.WriteLine($"[ERROR] Failed to read metadata: {eslockFilePath}");
                return;
            }

            if (string.IsNullOrEmpty(outputFilePath))
            {
                var directory = Path.GetDirectoryName(eslockFilePath);
                outputFilePath = Path.Combine(directory ?? "", metadata.OriginalFileName);
            }
            else
            {
                outputFilePath = Path.Combine(outputFilePath, metadata.OriginalFileName);
            }

            using var inputFileStream = new FileStream(eslockFilePath, FileMode.Open, FileAccess.Read);
            using var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);

            DecryptStream(inputFileStream, outputFileStream, metadata);

            Console.WriteLine($" -> Saved as: {Path.GetFileName(outputFilePath)}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[CRITICAL ERROR] while processing {eslockFilePath}: {ex.Message}");
        }
    }

    public static void DecryptDirectory(string inputDirectory, string outputDirectory)
    {
        var eslockFiles = Directory.GetFiles(inputDirectory, "*.eslock", SearchOption.AllDirectories);

        if (eslockFiles.Length == 0)
        {
            Console.WriteLine("No .eslock files found.");
            return;
        }

        Console.WriteLine($"Found {eslockFiles.Length} file(s). Starting parallel decryption...");

        Parallel.ForEach(eslockFiles, eslockFile =>
        {
            var relativePath = Path.GetRelativePath(inputDirectory, eslockFile);
            var metadata = EslockMetadata.Parse(eslockFile);
            if (metadata == null)
            {
                Console.WriteLine($"[ERROR] Skipping file (failed to read metadata): {eslockFile}");
                return;
            }

            DecryptFile(eslockFile, outputDirectory);
        });

        Console.WriteLine("Decryption of all files is complete.");
    }

    private static void DecryptStream(Stream inputStream, Stream outputStream, EslockMetadata metadata)
    {
        var cipher = CipherUtilities.GetCipher("AES/CFB/NoPadding");

        var keyParam = new KeyParameter(metadata.Key);
        var ivParam = new ParametersWithIV(keyParam, EslockMetadata.IV);
        cipher.Init(false, ivParam);

        long originalFileLength = inputStream.Length - metadata.FooterLength;
        const int bufferSize = 16384;
        var buffer = new byte[bufferSize];

        if (!metadata.IsPartial)
        {
            long bytesToProcess = originalFileLength;
            while (bytesToProcess > 0)
            {
                int bytesRead = inputStream.Read(buffer, 0, (int)Math.Min(buffer.Length, bytesToProcess));
                if (bytesRead == 0) break;

                var decryptedBytes = cipher.ProcessBytes(buffer, 0, bytesRead);
                if (decryptedBytes != null)
                {
                    outputStream.Write(decryptedBytes, 0, decryptedBytes.Length);
                }
                bytesToProcess -= bytesRead;
            }
        }
        else
        {
            long encryptedLength = metadata.EncryptedLength;
            long middlePartLength = originalFileLength - (2 * encryptedLength);

            var firstPart = new byte[encryptedLength];
            inputStream.ReadExactly(firstPart, 0, firstPart.Length);
            var decryptedFirst = cipher.ProcessBytes(firstPart);
            outputStream.Write(decryptedFirst, 0, decryptedFirst.Length);

            var middlePart = new byte[middlePartLength];
            inputStream.ReadExactly(middlePart, 0, middlePart.Length);
            outputStream.Write(middlePart, 0, middlePart.Length);

            var lastPart = new byte[encryptedLength];
            inputStream.ReadExactly(lastPart, 0, lastPart.Length);
            var decryptedLast = cipher.ProcessBytes(lastPart);
            outputStream.Write(decryptedLast, 0, decryptedLast.Length);
        }

        var finalBytes = cipher.DoFinal();
        if (finalBytes != null)
        {
            outputStream.Write(finalBytes, 0, finalBytes.Length);
        }
    }
}