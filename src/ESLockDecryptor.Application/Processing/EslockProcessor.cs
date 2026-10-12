using ESLockDecryptor.Application.Configuration;
using ESLockDecryptor.Application.Reporting;
using ESLockDecryptor.Core.Configuration;
using ESLockDecryptor.Core.Models;
using ESLockDecryptor.Core.IO;
using ESLockDecryptor.Core.Cryptography;
using ESLockDecryptor.Core.Services;

namespace ESLockDecryptor.Application.Processing;

public class EslockProcessor(ProcessingConfig config, IProcessingReporter? reporter = null)
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

        Reporter?.Info("\n================================================================================");
        Reporter?.Info("Processing complete.");
        Reporter?.Info($"  Files processed:  {Stats.FilesProcessed}");
        Reporter?.Info($"  Files decrypted:  {Stats.FilesDecrypted}");
        Reporter?.Info($"  Files skipped:    {Stats.FilesSkipped}");
        Reporter?.Info($"  Warnings:         {Stats.Warnings}");
        Reporter?.Info($"  Errors:           {Stats.Errors}");
        Reporter?.Info("================================================================================");
    }

    private void ProcessingFile(FileInfo inputFile, DirectoryInfo? outputDirectory)
    {
        using var report = Reporter?.BeginScope();
        report?.Info($"\nProcessing file: {inputFile.FullName}");
        EslockFooter? footer;

        try
        {
            if (Config.ReadOnly)
            {
                footer = ReadFooter(inputFile);
                if (footer is not null)
                {
                    LogMetadata(inputFile.Length, footer, report);
                    if (!footer.IsCrcValid)
                    {
                        report?.Warning("CRC check failed. Metadata may be corrupted.");
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
                report?.Info($"\nCreated output directory: {outputPath}");
            }

            if (Config.RawDecryptConfig is not null && !Config.Heuristic)
            {
                decryptConfig = GetDecryptionConfig(inputFile, null, report);
                outputPath = Path.Combine(outputDirectory.FullName, Path.GetFileNameWithoutExtension(inputFile.Name));

                DecryptFile(inputFile.FullName, outputPath, decryptConfig, report);
                report?.Success($"File decrypted: {inputFile.Name}");
                Stats.IncrementFilesDecrypted();
                return;
            }

            footer = ReadFooter(inputFile);
            decryptConfig = GetDecryptionConfig(inputFile, footer, report);
            string? originalFileName = footer?.EncryptedOriginalName is not null && footer.OriginalNameLength is not null
                ? Decryptor.DecryptFileName(footer.EncryptedOriginalName, decryptConfig.Key)
                : null;
            if (footer is not null && Config.Verbose)
            {
                LogMetadata(inputFile.Length, footer, report);
                if (originalFileName is not null)
                    report?.Info($"  Original file name: {originalFileName}");
            }
            if (footer is not null && !footer.IsCrcValid)
            {
                if (!Config.IgnoreCrc)
                {
                    throw new Exception("CRC check failed. Skipping file. Use '--ignore-crc' to bypass this check.");
                }
                report?.Warning("CRC check failed. Metadata may be corrupted.");
            }
            outputPath = Path.Combine(
                outputDirectory.FullName, 
                originalFileName ?? Path.GetFileNameWithoutExtension(inputFile.Name));

            DecryptFile(inputFile.FullName, outputPath, decryptConfig, report);
            report?.Success($"File decrypted: {inputFile.Name}");
            Stats.IncrementFilesDecrypted();
        }
        catch (Exception ex)
        {
            report?.Error(ex.Message);
            Stats.IncrementErrors();
            Stats.IncrementFilesSkipped();
            return;
        }
    }

    private void ProcessingDirectory(DirectoryInfo inputDirectory, DirectoryInfo? outputDirectory)
    {
        Reporter?.Info($"\nProcessing directory: {Config.InputPath.FullName}");

        var eslockFiles = Directory.GetFiles(inputDirectory.FullName, "*.eslock", SearchOption.AllDirectories);

        if (eslockFiles.Length == 0)
        {
            Reporter?.Info("  No .eslock files found.");
            return;
        }

        Reporter?.Info($"  Found {eslockFiles.Length} file(s).");

        if (!Config.ReadOnly && outputDirectory is not null && !Directory.Exists(outputDirectory.FullName))
        {
            Directory.CreateDirectory(outputDirectory.FullName);
            Reporter?.Info($"\nCreated output directory: {outputDirectory.FullName}");
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
        using var fileStream = new FileStream(
            file.FullName,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 1,
            options: FileOptions.RandomAccess);

        return footerReader.ReadFooter(fileStream);
    }

    private void LogMetadata(long fileLength, EslockFooter footer, IProcessingReportScope? report)
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

        if (report is null) return;

        report.Info($"  File size: {fileLength} bytes");
        report.Info($"  Footer offset: {footer.FooterOffset} bytes");
        report.Info("Metadata:");
        report.Info($"  Footer length: {footerLength} bytes");
        report.Info($"  CRC check: {crcStatus}");
        report.Info($"    Stored CRC: {storedCrc}");
        report.Info($"    Calculated CRC: {calculatedCrc}");
        report.Info($"  Encryption: {type}");
        report.Info($"  Key: {key}");
    }

    private DecryptionConfig GetDecryptionConfig(FileInfo file, EslockFooter? footer, IProcessingReportScope? report)
    {
        const bool isPartialDefault = true;     // most cases
        const int encryptedBlockDefault = 1024; // most cases

        long fileLength = file.Length;
        byte[] key = GetKey(footer, report);
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

    private byte[] GetKey(EslockFooter? footer, IProcessingReportScope? report)
    {
        if (Config.Key is not null)
        {
            report?.Info($"Using provided key: {Convert.ToHexString(Config.Key)}");
            return Config.Key;
            
        }
        if (Config.Password is not null)
        {
            report?.Info($"Using provided password: {Config.Password}");
            return KeyDerivator.DeriveKeyFromPassword(Config.Password);
        }
        if (footer is not null && footer.Key?.Length == 16)
        {
            return footer.Key;
        }
        throw new Exception("Key for decryption not found or corrupted.");
    }

    private void DecryptFile(string inputPath, string outputPath, DecryptionConfig config, IProcessingReportScope? report)
    {
        using var inputFileStream = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        try
        {
            FileMode mode = Config.Overwrite ? FileMode.Create : FileMode.CreateNew;
            using var outputFileStream = new FileStream(outputPath, mode, FileAccess.Write, FileShare.None);

            report?.Info($"Output path: {outputPath}");
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
    private IProcessingReporter? Reporter { get; } = reporter;
}