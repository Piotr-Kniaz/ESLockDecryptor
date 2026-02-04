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

        switch (InputPath)
        {
            case FileInfo fileInfo:
                ProcessingFile(fileInfo, OutputPath);
                break;

            case DirectoryInfo dirInfo:
                ProcessingDirectory(dirInfo, OutputPath);
                break;
        }

        PrintStats();
    }

    private void ProcessingFile(FileInfo inputFile, DirectoryInfo? outputDirectory)
    {
        BufferedConsoleLogger bufferedLogger = new();
        bufferedLogger.AddInfo($"\nProcessing file: {InputPath.FullName}");

        try
        {
            EslockFooter footer = ReadFooter(inputFile, bufferedLogger);
            if (!footer.IsCrcValid)
            {
                if (!IgnoreCrc)
                {
                    throw new Exception("CRC check failed. Skipping file. Use --ignore-crc to bypass this check.");
                }
                else
                {
                    bufferedLogger.AddWarning("CRC check failed. Metadata may be corrupted.");
                    Stats.IncrementWarnings();
                }
            }
        }
        catch (Exception ex)
        {
            bufferedLogger.AddError(ex.Message);
            Stats.IncrementErrors();
            Stats.IncrementFilesSkipped();
            return;
        }

        // Implementation of file processing logic goes here
    }

    private void ProcessingDirectory(DirectoryInfo inputDirectory, DirectoryInfo? outputDirectory)
    {
        Console.WriteLine($"\nProcessing directory: {InputPath.FullName}");

        // Implementation of directory processing logic goes here
    }

    private EslockFooter ReadFooter(FileInfo file, BufferedConsoleLogger logger)
    {
        IFooterReader footerReader = Heuristic ? new HeuristicFooterReader() : new StandardFooterReader();
        EslockFooter footer = footerReader.ReadFooter(file.FullName);

        if (Verbose || ReadOnly)
        {
            string crcStatus = footer.IsCrcValid ? "[MATCH]" : "[MISMATCH]";
            string type = footer.IsPartialEncryption
                ? $"Partial (encrypted first/last {footer.EncryptedBlockSize} bytes)"
                : "Full";

            logger.AddInfo($"  File size: {file.Length} bytes");
            logger.AddInfo($"  Footer length: {footer.FooterLength} bytes");
            // logger.AddInfo($"  Original name: {metadata.OriginalFileName}");
            logger.AddInfo($"  CRC check: {crcStatus}");
            logger.AddInfo($"    Stored CRC: {footer.StoredCrc:X8}");
            logger.AddInfo($"    Calculated CRC: {footer.CalculatedCrc:X8}");
            logger.AddInfo($"  Encryption: {type}");
            logger.AddInfo($"  Key: {Convert.ToHexString(footer.Key)}");
        }

        return footer;
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

    private FileSystemInfo InputPath { get => Config.InputPath; }
    private DirectoryInfo? OutputPath { get => Config.OutputPath; }
    private bool Verbose { get => Config.Verbose; }
    private bool Overwrite { get => Config.Overwrite; }
    private bool ReadOnly { get => Config.ReadOnly; }
    private bool IgnoreCrc { get => Config.IgnoreCrc; }
    private string? Password { get => Config.Password; }
    private string? Key { get => Config.Key; }
    private bool Heuristic { get => Config.Heuristic; }
    private RawDecryptConfig? RawDecryptConfig { get => Config.RawDecryptConfig; }
    private StatisticService Stats { get; } = new();
    private ProcessingConfig Config { get; } = config;
    private static string Version { get => Assembly.GetExecutingAssembly().GetName().Version?.ToString(2) ?? "---"; }
}