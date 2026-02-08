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

        try
        {
            if (Config.ReadOnly)
            {
                IFooterReader footerReader = Config.Heuristic ? new HeuristicFooterReader() : new StandardFooterReader();
                EslockFooter? footer = footerReader.ReadFooter(inputFile.FullName);
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

            if (Config.RawDecryptConfig is not null && !Config.Heuristic)
            {
                DecryptionConfig decryptionConfig = GetDecryptionConfig(inputFile, null, logger);
                var outputFilePath = Path.Combine(outputDirectory.FullName, inputFile.Name);

                using var inputFileStream = new FileStream(inputFile.FullName, FileMode.Open, FileAccess.Read, FileShare.Read);
                using var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);

                logger.AddInfo($"Output path: {outputFilePath}");
                Decryptor.DecryptStream(inputFileStream, outputFileStream, decryptionConfig);
                logger.AddSuccess($"File decrypted: {inputFile.Name}");
                return;
            }
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

        // Implementation of file processing logic goes here
    }

    private void ProcessingDirectory(DirectoryInfo inputDirectory, DirectoryInfo? outputDirectory)
    {
        Console.WriteLine($"\nProcessing directory: {Config.InputPath.FullName}");

        // Implementation of directory processing logic goes here
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
        // logger.AddInfo($"  Original name: {metadata.OriginalFileName}");
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
            return new DecryptionConfig()
            {
                OriginalFileLength = footer?.StartFooterPosition ?? fileLength,
                Key = key,
                IsPartialDecryption = footer?.IsPartialEncryption ?? isPartialProvided ?? isPartialDefault,
                EncryptedBlockSize = footer?.EncryptedBlockSize 
                    ?? Config.RawDecryptConfig.EncryptedBlockSize ?? encryptedBlockDefault,
                IsFileTruncated = footer is null
            };
        }
        if (footer is not null)
        {
            return new DecryptionConfig()
            {
                OriginalFileLength = footer.StartFooterPosition,
                Key = key,
                IsPartialDecryption = footer.IsPartialEncryption ?? isPartialDefault,
                EncryptedBlockSize = footer.EncryptedBlockSize ?? encryptedBlockDefault,
                IsFileTruncated = false
            };
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
    private Decryptor Decryptor { get; } = new();
    private static string Version { get => Assembly.GetExecutingAssembly().GetName().Version?.ToString(2) ?? "---"; }
}