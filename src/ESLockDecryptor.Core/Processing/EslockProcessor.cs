using ESLockDecryptor.Core.Configuration;
using ESLockDecryptor.Core.Models;
using ESLockDecryptor.Core.IO;
using ESLockDecryptor.Core.Cryptography;
using ESLockDecryptor.Core.Logging;
using ESLockDecryptor.Core.Services;

namespace ESLockDecryptor.Core.Processing;

public class EslockProcessor(ProcessingConfig config, ILogger? logger = null)
{
    public void Execute()
    {
        switch (Config.InputPath)
        {
            case FileInfo fileInfo:
                ProcessingFile(fileInfo, Config.OutputPath);
                break;

            case DirectoryInfo dirInfo:
                ProcessingDirectory(dirInfo, Config.OutputPath);
                break;
        }

        Logger?.AddInfo("\n================================================================================");
        Logger?.AddInfo("Processing complete.");
        Logger?.AddInfo($"  Files processed:  {Stats.FilesProcessed}");
        Logger?.AddInfo($"  Files decrypted:  {Stats.FilesDecrypted}");
        Logger?.AddInfo($"  Files skipped:    {Stats.FilesSkipped}");
        Logger?.AddInfo($"  Warnings:         {Stats.Warnings}");
        Logger?.AddInfo($"  Errors:           {Stats.Errors}");
        Logger?.AddInfo("================================================================================");
    }

    private void ProcessingFile(FileInfo inputFile, DirectoryInfo? outputDirectory)
    {
        Logger?.AddInfo($"\nProcessing file: {inputFile.FullName}");
        EslockFooter? footer;

        try
        {
            if (Config.ReadOnly)
            {
                footer = ReadFooter(inputFile);
                if (footer is not null)
                {
                    LogMetadata(inputFile.Length, footer);
                    if (!footer.IsCrcValid)
                    {
                        Logger?.AddWarning("CRC check failed. Metadata may be corrupted.");
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
                Logger?.AddInfo($"\nCreated output directory: {outputPath}");
            }

            if (Config.RawDecryptConfig is not null && !Config.Heuristic)
            {
                decryptConfig = GetDecryptionConfig(inputFile, null);
                outputPath = Path.Combine(outputDirectory.FullName, Path.GetFileNameWithoutExtension(inputFile.Name));

                DecryptFile(inputFile.FullName, outputPath, decryptConfig);
                Logger?.AddSuccess($"File decrypted: {inputFile.Name}");
                Stats.IncrementFilesDecrypted();
                return;
            }

            footer = ReadFooter(inputFile);
            decryptConfig = GetDecryptionConfig(inputFile, footer);
            string? originalFileName = footer?.EncryptedOriginalName is not null && footer.OriginalNameLength is not null
                ? Decryptor.DecryptFileName(footer.EncryptedOriginalName, decryptConfig.Key)
                : null;
            if (footer is not null && Config.Verbose)
            {
                LogMetadata(inputFile.Length, footer);
                if (originalFileName is not null)
                    Logger?.AddInfo($"  Original file name: {originalFileName}");
            }
            if (footer is not null && !footer.IsCrcValid)
            {
                if (!Config.IgnoreCrc)
                {
                    throw new Exception("CRC check failed. Skipping file. Use '--ignore-crc' to bypass this check.");
                }
                Logger?.AddWarning("CRC check failed. Metadata may be corrupted.");
            }
            outputPath = Path.Combine(
                outputDirectory.FullName, 
                originalFileName ?? Path.GetFileNameWithoutExtension(inputFile.Name));

            DecryptFile(inputFile.FullName, outputPath, decryptConfig);
            Logger?.AddSuccess($"File decrypted: {inputFile.Name}");
            Stats.IncrementFilesDecrypted();
        }
        catch (Exception ex)
        {
            Logger?.AddError(ex.Message);
            Stats.IncrementErrors();
            Stats.IncrementFilesSkipped();
            return;
        }
    }

    private void ProcessingDirectory(DirectoryInfo inputDirectory, DirectoryInfo? outputDirectory)
    {
        Logger?.AddInfo($"\nProcessing directory: {Config.InputPath.FullName}");

        var eslockFiles = Directory.GetFiles(inputDirectory.FullName, "*.eslock", SearchOption.AllDirectories);

        if (eslockFiles.Length == 0)
        {
            Logger?.AddInfo("  No .eslock files found.");
            return;
        }

        Logger?.AddInfo($"  Found {eslockFiles.Length} file(s).");

        if (!Config.ReadOnly && outputDirectory is not null && !Directory.Exists(outputDirectory.FullName))
        {
            Directory.CreateDirectory(outputDirectory.FullName);
            Logger?.AddInfo($"\nCreated output directory: {outputDirectory.FullName}");
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

    private void LogMetadata(long fileLength, EslockFooter footer)
    {
        string unknown = "unknown";
        string crcStatus = footer.IsCrcValid ? "[MATCH]" : "[MISMATCH]";
        string storedCrc = footer.StoredCrc is not null ? string.Format("{0:X8}", footer.StoredCrc) : unknown;
        string calculatedCrc = footer.CalculatedCrc is not null ? string.Format("{0:X8}", footer.CalculatedCrc) : unknown;
        string footerLength = footer.FooterLength is not null ? footer.FooterLength.ToString() ?? unknown : unknown;
        string type = footer.IsPartialEncryption switch
        {
            null => unknown,
            true => $"Partial (encrypted first/last {footer.EncryptedBlockSize.ToString() ?? unknown} bytes)",
            false => "Full"
        };
        string key = footer.Key is not null ? Convert.ToHexString(footer.Key) : unknown;

        if (Logger is null) return;

        Logger.AddInfo($"  File size: {fileLength} bytes");
        Logger.AddInfo($"  Footer offset: {footer.FooterOffset} bytes");
        Logger.AddInfo("Metadata:");
        Logger.AddInfo($"  Footer length: {footerLength} bytes");
        Logger.AddInfo($"  CRC check: {crcStatus}");
        Logger.AddInfo($"    Stored CRC: {storedCrc}");
        Logger.AddInfo($"    Calculated CRC: {calculatedCrc}");
        Logger.AddInfo($"  Encryption: {type}");
        Logger.AddInfo($"  Key: {key}");
    }

    private DecryptionConfig GetDecryptionConfig(FileInfo file, EslockFooter? footer)
    {
        const bool isPartialDefault = true;     // most cases
        const int encryptedBlockDefault = 1024; // most cases

        long fileLength = file.Length;
        byte[] key = GetKey(footer);
        bool? isPartialProvided = Config.RawDecryptConfig?.Mode.IsPartialProvided;

        if (Config.RawDecryptConfig is not null)
        {
            bool isPartial = isPartialProvided ?? footer?.IsPartialEncryption ?? isPartialDefault;
            if (isPartial)
            {
                return DecryptionConfig.CreatePartialEncrypt(
                    originalFileLength: footer?.FooterOffset ?? fileLength,
                    key: key,
                    encryptedBlockSize: Config.RawDecryptConfig.EncryptedBlockSize
                        ?? footer?.EncryptedBlockSize ?? encryptedBlockDefault,
                    isFileTruncated: footer is null
                );
            }
            else
            {
                return DecryptionConfig.CreateFullEncrypt(
                    originalFileLength: footer?.FooterOffset ?? fileLength,
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
                    originalFileLength: footer.FooterOffset,
                    key: key,
                    encryptedBlockSize: footer.EncryptedBlockSize ?? encryptedBlockDefault,
                    isFileTruncated: false
                );
            }
            else
            {
                return DecryptionConfig.CreateFullEncrypt(
                    originalFileLength: footer.FooterOffset,
                    key: key,
                    isFileTruncated: false
                );
            }
        }
        throw new InvalidDataException("Not enough data to decrypt.");
    }

    private byte[] GetKey(EslockFooter? footer)
    {
        if (Config.Key is not null)
        {
            Logger?.AddInfo($"Using provided key: {Convert.ToHexString(Config.Key)}");
            return Config.Key;
            
        }
        if (Config.Password is not null)
        {
            Logger?.AddInfo($"Using provided password: {Config.Password}");
            return KeyDerivator.DeriveKeyFromPassword(Config.Password);
        }
        if (footer is not null && footer.Key?.Length == 16)
        {
            return footer.Key;
        }
        throw new Exception("Key for decryption not found or corrupted.");
    }

    private void DecryptFile(string inputPath, string outputPath, DecryptionConfig config)
    {
        using var inputFileStream = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        try
        {
            FileMode mode = Config.Overwrite ? FileMode.Create : FileMode.CreateNew;
            using var outputFileStream = new FileStream(outputPath, mode, FileAccess.Write, FileShare.None);

            Logger?.AddInfo($"Output path: {outputPath}");
            Decryptor.DecryptStream(inputFileStream, outputFileStream, config);
        }
        catch (IOException) when (!Config.Overwrite && File.Exists(outputPath))
        {
            throw new Exception($"File {Path.GetFileName(outputPath)} exists in the output directory. "
                + "Use '--overwrite' to replace existing file.");
        }
        catch (IOException ex)
        {
            throw new Exception($"Failed to access output file. Details: {ex.Message}");
        }
    }

    private StatisticService Stats { get; } = new();
    private ProcessingConfig Config { get; } = config;
    private ILogger? Logger { get; } = logger;
}