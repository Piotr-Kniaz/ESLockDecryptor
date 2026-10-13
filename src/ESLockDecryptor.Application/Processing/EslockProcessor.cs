using ESLockDecryptor.Application.Configuration;
using ESLockDecryptor.Application.Reporting;
using ESLockDecryptor.Core.Configuration;
using ESLockDecryptor.Core.Models;
using ESLockDecryptor.Core.Processing;
using ESLockDecryptor.Application.Services;

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

        try
        {
            if (!Config.ReadOnly && outputDirectory is null)
            {
                throw new Exception("Output directory must be specified.");
            }

            if (outputDirectory is not null && !Directory.Exists(outputDirectory.FullName))
            {
                Directory.CreateDirectory(outputDirectory.FullName);
                report?.Info($"\nCreated output directory: {outputDirectory.FullName}");
            }

            using var inputStream = new FileStream(
                inputFile.FullName,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 1,
                options: FileOptions.RandomAccess);

            var options = new DecryptionOptions
            {
                Key = Config.Key,
                Password = Config.Password,
                IgnoreCrc = Config.ReadOnly || Config.IgnoreCrc,
                Heuristic = Config.Heuristic,
                RawDecrypt = Config.RawDecryptConfig
            };

            if (Config.ReadOnly)
            {
                var footer = EslockFileDecryptor.ReadFooter(inputStream, Config.Heuristic);
                LogMetadata(inputFile.Length, footer, report);
                if (!footer.IsCrcValid)
                {
                    report?.Warning("CRC check failed. Metadata may be corrupted.");
                    Stats.IncrementWarnings();
                }
                Stats.IncrementFilesProcessed();
                return;
            }

            var plan = EslockFileDecryptor.Prepare(inputStream, options);

            if (plan.Footer is not null && (Config.ReadOnly || Config.Verbose))
            {
                LogMetadata(inputFile.Length, plan.Footer, report);
                if (plan.OriginalFileName is not null)
                    report?.Info($"  Original file name: {plan.OriginalFileName}");
            }

            if (plan.Footer is not null && !plan.Footer.IsCrcValid)
            {
                report?.Warning("CRC check failed. Metadata may be corrupted.");
                Stats.IncrementWarnings();
            }

            string outputPath = Path.Combine(
                outputDirectory!.FullName,
                plan.OriginalFileName ?? Path.GetFileNameWithoutExtension(inputFile.Name));

            DecryptFile(inputStream, outputPath, plan, report);
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

    private void DecryptFile(
        Stream inputStream,
        string outputPath,
        DecryptionPlan plan,
        IProcessingReportScope? report)
    {
        try
        {
            FileMode mode = Config.Overwrite ? FileMode.Create : FileMode.CreateNew;
            using var outputFileStream = new FileStream(outputPath, mode, FileAccess.Write, FileShare.None);

            report?.Info($"Output path: {outputPath}");
            EslockFileDecryptor.Decrypt(inputStream, outputFileStream, plan);
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