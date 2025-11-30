using System.Security.Cryptography;

namespace ESLockDecryptor;

public static class EslockDecryptor
{
    public static void DecryptFile(string eslockFilePath, string outputFilePath)
    {
        Console.WriteLine($"Start decrypting: {Path.GetFileName(eslockFilePath)}");
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

            using var inputFileStream = new FileStream(eslockFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
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

        Console.WriteLine($"\nFound {eslockFiles.Length} file(s). Starting parallel decryption...");

        Parallel.ForEach(eslockFiles, eslockFile =>
        {
            var metadata = EslockMetadata.Parse(eslockFile);
            if (metadata == null)
            {
                Console.WriteLine($"[ERROR] Skipping file (failed to read metadata): {eslockFile}");
                return;
            }

            var relativePath = Path.GetRelativePath(inputDirectory, eslockFile);
            var relativeDir = Path.GetDirectoryName(relativePath);

            var targetDirectory = string.IsNullOrEmpty(relativeDir)
                ? outputDirectory
                : Path.Combine(outputDirectory, relativeDir);

            Directory.CreateDirectory(targetDirectory);

            DecryptFile(eslockFile, targetDirectory);
        });

        Console.WriteLine("=======================================================");
        Console.WriteLine("Decryption of all files is complete.");
    }

    private static void DecryptStream(Stream inputStream, Stream outputStream, EslockMetadata metadata)
    {
        using var aes = Aes.Create();
        aes.Key = metadata.Key;
        aes.IV = EslockMetadata.IV;
        aes.Mode = CipherMode.CFB;
        aes.Padding = PaddingMode.None;
        aes.FeedbackSize = 128;

        using var decryptor = aes.CreateDecryptor();

        long originalFileLength = inputStream.Length - metadata.FooterLength;

        if (!metadata.IsPartial)
        {
            using var cryptoStream = new CryptoStream(inputStream, decryptor, CryptoStreamMode.Read);

            byte[] buffer = new byte[81920];
            long bytesToProcess = originalFileLength;

            while (bytesToProcess > 0)
            {
                int bytesRead = cryptoStream.Read(buffer, 0, (int)Math.Min(buffer.Length, bytesToProcess));
                if (bytesRead == 0) break;

                outputStream.Write(buffer, 0, bytesRead);
                bytesToProcess -= bytesRead;
            }
        }
        else
        {
            long encryptedLength = metadata.EncryptedLength;
            long middlePartLength = originalFileLength - (2 * encryptedLength);

            var firstPart = new byte[encryptedLength];
            inputStream.ReadExactly(firstPart, 0, firstPart.Length);
            var decryptedFirstBytes = decryptor.TransformFinalBlock(firstPart, 0, firstPart.Length);
            outputStream.Write(decryptedFirstBytes, 0, decryptedFirstBytes.Length);

            if (middlePartLength > 0)
            {
                inputStream.CopyTo(outputStream, middlePartLength);
            }

            using var finalDecryptor = aes.CreateDecryptor();
            var lastPart = new byte[encryptedLength];
            inputStream.ReadExactly(lastPart, 0, lastPart.Length);
            var decryptedLastBytes = finalDecryptor.TransformFinalBlock(lastPart, 0, lastPart.Length);
            outputStream.Write(decryptedLastBytes, 0, decryptedLastBytes.Length);
        }
    }
}

public static class StreamExtensions
{
    public static void CopyTo(this Stream source, Stream destination, long count)
    {
        byte[] buffer = new byte[81920];
        long bytesCopied = 0;

        while (bytesCopied < count)
        {
            int bytesToRead = (int)Math.Min(buffer.Length, count - bytesCopied);
            int bytesRead = source.Read(buffer, 0, bytesToRead);

            if (bytesRead == 0)
            {
                break;
            }

            destination.Write(buffer, 0, bytesRead);
            bytesCopied += bytesRead;
        }
    }
}