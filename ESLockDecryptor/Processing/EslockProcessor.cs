using System.Reflection;
using ESLockDecryptor.Configuration;
using ESLockDecryptor.Models;
using ESLockDecryptor.IO;
using ESLockDecryptor.Cryptography;
using ESLockDecryptor.Logging;
using ESLockDecryptor.Services;

namespace ESLockDecryptor.Processing;

public class EslockProcessor(ProcessingConfig config)
{
    public void Execute()
    {
        PrintInfo();

        switch (Config.InputPath)
        {
            case FileInfo fileInfo:
                ProcessingFile(fileInfo, Config.OutputPath);
                break;

            case DirectoryInfo dirInfo:
                ProcessingDirectory(dirInfo, Config.OutputPath);
                break;
        }

        PrintStats();
    }

    private void ProcessingFile(FileInfo inputFile, DirectoryInfo? outputDirectory)
    {
        BufferedConsoleLogger logger = new();
        logger.AddInfo($"\nProcessing file: {inputFile.FullName}");
        EslockFooter? footer;

        try
        {
            if (Config.ReadOnly)
            {
                footer = ReadFooter(inputFile);
                if (footer is not null)
                {
                    LogMetadata(inputFile.Length, footer, logger);
                    if (!footer.IsCrcValid)
                    {
                        logger.AddWarning("CRC check failed. Metadata may be corrupted.");
                        Stats.IncrementWarnings();
                    }
                    Stats.IncrementFilesProcessed();
                    return;
                }
                else
                {
                    throw new Exception("Footer not found.");
                }
            }
            else if (outputDirectory is null)
            {
                throw new Exception("Output directory must be specified.");
            }

            string outputPath = outputDirectory.FullName;
            DecryptionConfig decryptConfig;

            if (!Directory.Exists(outputPath))
            {
                Directory.CreateDirectory(outputPath);
                logger.AddInfo($"\nCreated output directory: {outputPath}");
            }

            if (Config.RawDecryptConfig is not null && !Config.Heuristic)
            {
                decryptConfig = GetDecryptionConfig(inputFile, null, logger);
                outputPath = Path.Combine(outputDirectory.FullName, Path.GetFileNameWithoutExtension(inputFile.Name));

                if (File.Exists(outputPath) && !Config.Overwrite)
                {
                    throw new Exception($"File {Path.GetFileNameWithoutExtension(outputPath)} exists in the output directory. "
                        + "Use '--overwrite' to replace existing file.");
                }

                DecryptFile(inputFile.FullName, outputPath, decryptConfig, logger);
                logger.AddSuccess($"File decrypted: {inputFile.Name}");
                Stats.IncrementFilesDecrypted();
                return;
            }

            footer = ReadFooter(inputFile);
            decryptConfig = GetDecryptionConfig(inputFile, footer, logger);
            string? originalFileName = footer?.EncryptedOriginalName is not null && footer.OriginalNameLength is not null
                ? Decryptor.DecryptFileName(footer.EncryptedOriginalName, decryptConfig.Key, (int)footer.OriginalNameLength)
                : null;
            if (footer is not null && Config.Verbose)
            {
                LogMetadata(inputFile.Length, footer, logger);
                if (originalFileName is not null)
                    logger.AddInfo($"  Original file name: {originalFileName}");
            }
            if (footer is not null && !footer.IsCrcValid)
            {
                if (!Config.IgnoreCrc)
                {
                    throw new Exception("CRC check failed. Skipping file. Use '--ignore-crc' to bypass this check.");
                }
                logger.AddWarning("CRC check failed. Metadata may be corrupted.");
            }
            outputPath = Path.Combine(
                outputDirectory.FullName, 
                originalFileName ?? Path.GetFileNameWithoutExtension(inputFile.Name));

            if (File.Exists(outputPath) && !Config.Overwrite)
            {
                throw new Exception($"File {Path.GetFileNameWithoutExtension(outputPath)} exists in the output directory. "
                    + "Use '--overwrite' to replace existing file.");
            }

            DecryptFile(inputFile.FullName, outputPath, decryptConfig, logger);
            logger.AddSuccess($"File decrypted: {inputFile.Name}");
            Stats.IncrementFilesDecrypted();
        }
        catch (Exception ex)
        {
            logger.AddError(ex.Message);
            Stats.IncrementErrors();
            Stats.IncrementFilesSkipped();
            return;
        }
        finally
        {
            logger.Flush();
        }
    }

    private void ProcessingDirectory(DirectoryInfo inputDirectory, DirectoryInfo? outputDirectory)
    {
        Console.WriteLine($"\nProcessing directory: {Config.InputPath.FullName}");

        var eslockFiles = Directory.GetFiles(inputDirectory.FullName, "*.eslock", SearchOption.AllDirectories);

        if (eslockFiles.Length == 0)
        {
            Console.WriteLine("  No .eslock files found.");
            return;
        }

        Console.WriteLine($"  Found {eslockFiles.Length} file(s).");

        if (!Config.ReadOnly && outputDirectory is not null && !Directory.Exists(outputDirectory.FullName))
        {
            Directory.CreateDirectory(outputDirectory.FullName);
            Console.WriteLine($"\nCreated output directory: {outputDirectory.FullName}");
        }

        Parallel.ForEach(eslockFiles, eslockFile =>
        {
            if (!Config.ReadOnly && outputDirectory is not null)
            {
                var relativePath = Path.GetRelativePath(inputDirectory.FullName, eslockFile);
                var relativeDir = Path.GetDirectoryName(relativePath);

                var targetDirectory = string.IsNullOrEmpty(relativeDir)
                    ? outputDirectory.FullName
                    : Path.Combine(outputDirectory.FullName, relativeDir);

                Directory.CreateDirectory(targetDirectory);

                ProcessingFile(new FileInfo(eslockFile), new DirectoryInfo(targetDirectory));
            }
            else
            {
                ProcessingFile(new FileInfo(eslockFile), null);
            }
        });
    }

    private EslockFooter? ReadFooter(FileInfo file)
    {
        IFooterReader footerReader = Config.Heuristic ? new HeuristicFooterReader() : new StandardFooterReader();
        return footerReader.ReadFooter(file.FullName);
    }
    private void LogMetadata(long fileLength, EslockFooter footer, BufferedConsoleLogger logger)
    {
        string unknown = "unknown";
        string crcStatus = footer.IsCrcValid ? "[MATCH]" : "[MISMATCH]";
        string storedCrc = footer.StoredCrc is not null ? string.Format("{0:X8}", footer.StoredCrc) : unknown;
        string calculatedCrc = footer.CalculatedCrc is not null ? string.Format("{0:X8}", footer.CalculatedCrc) : unknown;
        string type = footer.IsPartialEncryption switch
        {
            null => unknown,
            true => $"Partial (encrypted first/last {footer.EncryptedBlockSize.ToString() ?? unknown} bytes)",
            false => "Full"
        };
        string key = footer.Key is not null ? Convert.ToHexString(footer.Key) : unknown;

        logger.AddInfo("File metadata:");
        logger.AddInfo($"  File size: {fileLength} bytes");
        logger.AddInfo($"  Footer length: {footer.FooterLength.ToString() ?? unknown} bytes");
        logger.AddInfo($"  CRC check: {crcStatus}");
        logger.AddInfo($"    Stored CRC: {storedCrc}");
        logger.AddInfo($"    Calculated CRC: {calculatedCrc}");
        logger.AddInfo($"  Encryption: {type}");
        logger.AddInfo($"  Key: {key}");
    }

    private DecryptionConfig GetDecryptionConfig(FileInfo file, EslockFooter? footer, BufferedConsoleLogger logger)
    {
        long fileLength = file.Length;
        byte[] key = GetKey(footer, logger);
        bool isPartialDefault = fileLength > 2000; // TODO: Research!
        int encryptedBlockDefault = 1024; // TODO: Research!
        bool? isPartialProvided = Config.RawDecryptConfig?.Mode switch
        {
            RawDecryptMode.Partial => true,
            RawDecryptMode.Full => false,
            _ => null
        };

        if (Config.RawDecryptConfig is not null)
        {
            bool isPartial = isPartialProvided ?? footer?.IsPartialEncryption ?? isPartialDefault;
            if (isPartial)
            {
                return DecryptionConfig.CreatePartialEncrypt(
                    originalFileLength: footer?.StartFooterPosition ?? fileLength,
                    key: key,
                    encryptedBlockSize: Config.RawDecryptConfig.EncryptedBlockSize
                        ?? footer?.EncryptedBlockSize ?? encryptedBlockDefault,
                    isFileTruncated: footer is null
                );
            }
            else
            {
                return DecryptionConfig.CreateFullEncrypt(
                    originalFileLength: footer?.StartFooterPosition ?? fileLength,
                    key: key,
                    isFileTruncated: footer is null
                );
            }
        }
        if (footer is not null)
        {
            bool isPartial = footer.IsPartialEncryption ?? isPartialDefault;
            if (isPartial)
            {
                return DecryptionConfig.CreatePartialEncrypt(
                    originalFileLength: footer.StartFooterPosition,
                    key: key,
                    encryptedBlockSize: footer.EncryptedBlockSize ?? encryptedBlockDefault,
                    isFileTruncated: false
                );
            }
            else
            {
                return DecryptionConfig.CreateFullEncrypt(
                    originalFileLength: footer.StartFooterPosition,
                    key: key,
                    isFileTruncated: false
                );
            }
        }
        throw new InvalidDataException("Not enough data to decrypt.");
    }

    private byte[] GetKey(EslockFooter? footer, BufferedConsoleLogger logger)
    {
        if (Config.Key is not null)
        {
            logger.AddInfo($"Using provided key: {Convert.ToHexString(Config.Key)}");
            return Config.Key;
            
        }
        if (Config.Password is not null)
        {
            logger.AddInfo($"Using provided password: {Config.Password}");
            return KeyDerivator.DeriveKeyFromPassword(Config.Password);
        }
        if (footer is not null && footer.Key?.Length == 16)
        {
            return footer.Key;
        }
        throw new Exception("Key for decryption not found or corrupted.");
    }

    private void DecryptFile(string inputPath, string outputPath, DecryptionConfig config, BufferedConsoleLogger logger)
    {
        using var inputFileStream = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var outputFileStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write);

        logger.AddInfo($"Output path: {outputPath}");
        Decryptor.DecryptStream(inputFileStream, outputFileStream, config);
    }

    private static void PrintInfo()
    {
        Console.WriteLine("================================================================================");
        Console.WriteLine("                                 ESLockDecryptor");
        Console.WriteLine("================================================================================");
        Console.WriteLine("     Forensic tool for recovering ES File Explorer encrypted files (.eslock)");
        Console.WriteLine("                             ! FOR LEGAL USE ONLY !");
        Console.WriteLine($"              Version {Version} | (C) 2025-2026 Piotr Kniaz | MIT License");
        Console.WriteLine("================================================================================");
    }

    private void PrintStats()
    {
        Console.WriteLine("\n================================================================================");
        Console.WriteLine("Processing complete.");
        Console.WriteLine($"  Files processed:  {Stats.FilesProcessed}");
        Console.WriteLine($"  Files decrypted:  {Stats.FilesDecrypted}");
        Console.WriteLine($"  Files skipped:    {Stats.FilesSkipped}");
        Console.WriteLine($"  Warnings:         {Stats.Warnings}");
        Console.WriteLine($"  Errors:           {Stats.Errors}");
        Console.WriteLine("================================================================================");
    }

    private StatisticService Stats { get; } = new();
    private ProcessingConfig Config { get; } = config;
    private static string Version { get => Assembly.GetExecutingAssembly().GetName().Version?.ToString(2) ?? "---"; }
}