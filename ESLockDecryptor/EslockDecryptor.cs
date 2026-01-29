using System.CommandLine;
using System.Security.Cryptography;
using ESLockDecryptor.Services;

namespace ESLockDecryptor;

public static class EslockDecryptor
{
    public static void DecryptFile(string inputFilePath, string outputFilePath, Options options)
    {
        var logBuffer = new LogBuffer();
        logBuffer.AddLine($"\nFile processing: {Path.GetFileName(inputFilePath)}");

        try
        {
            var metadata = EslockMetadata.Parse(inputFilePath);

            if (!options.IgnoreCrc && !metadata.CrcValid)
            {
                logBuffer.AddLine($"[ERROR] CRC check failed. Skipping file. Use --ignore-crc to bypass this check.");
                FilesSkipped++;
                return;
            }

            if (options.ExtractKeyOnly)
            {
                logBuffer.AddLine($"  Key: {Convert.ToHexString(metadata.Key)}");
                if (!metadata.CrcValid)
                    logBuffer.AddLine("[WARNING] CRC check failed. Key may be corrupted.");

                TotalFilesProcessed++;
                return;
            }

            if (options.Verbose)
            {
                string crcStatus = metadata.CrcValid ? "[MATCH]" : "[MISMATCH]";
                string type = metadata.IsPartial ? $"Partial (encrypted first/last {metadata.EncryptedLength} bytes)" : "Full";

                logBuffer.AddLine($"  File size: {new FileInfo(inputFilePath).Length} bytes");
                logBuffer.AddLine($"  Footer length: {metadata.FooterLength} bytes");
                logBuffer.AddLine($"  Original name: {metadata.OriginalFileName}");
                logBuffer.AddLine($"  CRC check: {crcStatus}");
                logBuffer.AddLine($"    Stored CRC: {metadata.StoredCrc:X8}");
                logBuffer.AddLine($"    Calculated CRC: {metadata.CalculatedCrc:X8}");
                logBuffer.AddLine($"  Encryption: {type}");
                logBuffer.AddLine($"  Key: {Convert.ToHexString(metadata.Key)}");
            }

            if (!metadata.CrcValid)
            {
                logBuffer.AddLine("[WARNING] CRC check failed. Metadata may be corrupted.");
            }

            if (string.IsNullOrEmpty(outputFilePath))
            {
                var directory = Path.GetDirectoryName(inputFilePath);
                outputFilePath = Path.Combine(directory ?? "", metadata.OriginalFileName);
            }
            else
            {
                outputFilePath = Path.Combine(outputFilePath, metadata.OriginalFileName);
            }

            logBuffer.AddLine($"  Target path: {Path.GetFullPath(outputFilePath)}");

            if (File.Exists(outputFilePath) && !options.Overwrite)
            {
                logBuffer.AddLine("[ERROR] Output file already exists. Use --overwrite to replace it.");
                FilesSkipped++;
                return;
            }

            if (File.Exists(outputFilePath))
            {
                logBuffer.AddLine("[WARNING] Output file already exists. It will be overwritten.");
            }

            using var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);

            DecryptStream(inputFileStream, outputFileStream, metadata);

            logBuffer.AddLine($"[SUCCESS] Decrypted: {Path.GetFileName(outputFilePath)}");
            FilesDecrypted++;
        }
        catch (Exception ex)
        {
            logBuffer.AddLine($"[ERROR] {ex.Message}");
        }
        finally
        {
            logBuffer.PrintBuffer();
        }
    }

    public static void DecryptDirectory(string inputDirectory, string outputDirectory, Options options)
    {
        Console.WriteLine($"\nRecursive directory processing: {inputDirectory}");

        var eslockFiles = Directory.GetFiles(inputDirectory, "*.eslock", SearchOption.AllDirectories);

        if (eslockFiles.Length == 0)
        {
            Console.WriteLine("  No .eslock files found.");
            return;
        }

        Console.WriteLine($"  Found {eslockFiles.Length} file(s).");

        Parallel.ForEach(eslockFiles, eslockFile =>
        {
            var relativePath = Path.GetRelativePath(inputDirectory, eslockFile);
            var relativeDir = Path.GetDirectoryName(relativePath);

            var targetDirectory = string.IsNullOrEmpty(relativeDir)
                ? outputDirectory
                : Path.Combine(outputDirectory, relativeDir);

            Directory.CreateDirectory(targetDirectory);

            DecryptFile(eslockFile, targetDirectory, options);
        });
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

    public static int TotalFilesProcessed { get; private set; } = 0;
    public static int FilesDecrypted
    {
        get;
        private set
        {
            FilesDecrypted = value;
            TotalFilesProcessed++;
        }
    } = 0;
    public static int FilesSkipped
    {
        get;
        private set
        {
            FilesSkipped = value;
            TotalFilesProcessed++;
        }
    } = 0;
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