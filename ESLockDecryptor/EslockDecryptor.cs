using System.Security.Cryptography;
using ESLockDecryptor.Services;

namespace ESLockDecryptor;

public static class EslockDecryptor
{
    public static void DecryptFile(string inputFilePath, string outputFilePath, Options options, byte[]? providedKey = null)
    {
        var logBuffer = new LogBuffer();
        logBuffer.AddLine($"\nFile processing: {Path.GetFileName(inputFilePath)}");

        try
        {
            var metadata = EslockMetadata.Parse(inputFilePath);

            if (!options.IgnoreCrc && !metadata.CrcValid)
            {
                logBuffer.AddLine($"[ERROR] CRC check failed. Skipping file. Use --ignore-crc to bypass this check.");
                IncrementErrors();
                IncrementFilesSkipped();
                return;
            }

            if (options.ExtractKeyOnly)
            {
                logBuffer.AddLine($"  Key: {Convert.ToHexString(metadata.Key)}");
                if (!metadata.CrcValid)
                {
                    logBuffer.AddLine("[WARNING] CRC check failed. Key may be corrupted.");
                    IncrementWarnings();
                }

                IncrementFilesProcessed();
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
                IncrementWarnings();
            }

            if (!Directory.Exists(outputFilePath))
            {
                Directory.CreateDirectory(outputFilePath);
                Console.WriteLine($"Created output directory: {outputFilePath}");
            }

            outputFilePath = Path.Combine(outputFilePath, metadata.OriginalFileName);

            logBuffer.AddLine($"  Target path: {Path.GetFullPath(outputFilePath)}");

            if (File.Exists(outputFilePath) && !options.Overwrite)
            {
                logBuffer.AddLine("[ERROR] Output file already exists. Use --overwrite to replace it.");
                IncrementErrors();
                IncrementFilesSkipped();
                return;
            }

            if (File.Exists(outputFilePath))
            {
                logBuffer.AddLine("[WARNING] Output file already exists. It will be overwritten.");
                IncrementWarnings();
            }

            using var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);

            if (options.Password is not null)
            {
                logBuffer.AddLine($"Using provided password: {options.Password}");
                providedKey ??= GetKeyFromPassword(options.Password);
            }
            else if (options.Key is not null)
            {
                logBuffer.AddLine($"Using provided key: {options.Key}");
                providedKey ??= Convert.FromHexString(options.Key);
            }

            DecryptStream(inputFileStream, outputFileStream, metadata, providedKey);

            logBuffer.AddLine($"[SUCCESS] Decrypted: {Path.GetFileName(outputFilePath)}");
            IncrementFilesDecrypted();
        }
        catch (Exception ex)
        {
            logBuffer.AddLine($"[ERROR] {ex.Message}");
            IncrementErrors();
            IncrementFilesSkipped();
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

        if (!Directory.Exists(outputDirectory))
        {
            Directory.CreateDirectory(outputDirectory);
            Console.WriteLine($"Created output directory: {outputDirectory}");
        }

        byte[]? providedKey = null;
        
        if (options.Key is not null)
            providedKey = Convert.FromHexString(options.Key);
        else if (options.Password is not null)
            providedKey = GetKeyFromPassword(options.Password);

        Parallel.ForEach(eslockFiles, eslockFile =>
        {
            var relativePath = Path.GetRelativePath(inputDirectory, eslockFile);
            var relativeDir = Path.GetDirectoryName(relativePath);

            var targetDirectory = string.IsNullOrEmpty(relativeDir)
                ? outputDirectory
                : Path.Combine(outputDirectory, relativeDir);

            Directory.CreateDirectory(targetDirectory);

            DecryptFile(eslockFile, targetDirectory, options, providedKey);
        });
    }

    private static void DecryptStream(Stream inputStream, Stream outputStream, EslockMetadata metadata, byte[]? providedKey = null)
    {
        using var aes = Aes.Create();
        aes.Key = providedKey ?? metadata.Key;
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

    private static byte[] GetKeyFromPassword(string password) =>
        [.. MD5.HashData(System.Text.Encoding.UTF8.GetBytes(password)).Take(16)];

    private static void IncrementFilesProcessed() => Interlocked.Increment(ref _filesProcessed);
    private static void IncrementFilesDecrypted()
    {
        Interlocked.Increment(ref _filesDecrypted);
        Interlocked.Increment(ref _filesProcessed);
    }
    private static void IncrementFilesSkipped()
    {
        Interlocked.Increment(ref _filesSkipped);
        Interlocked.Increment(ref _filesProcessed);
    }
    private static void IncrementErrors() => Interlocked.Increment(ref _errors);
    private static void IncrementWarnings() => Interlocked.Increment(ref _warnings);

    public static int FilesProcessed { get => _filesProcessed; }
    public static int FilesDecrypted { get => _filesDecrypted; }
    public static int FilesSkipped { get => _filesSkipped; }
    public static int Errors { get => _errors; }
    public static int Warnings { get => _warnings; }

    private static int _filesProcessed = 0;
    private static int _filesDecrypted = 0;
    private static int _filesSkipped = 0;
    private static int _errors = 0;
    private static int _warnings = 0;
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