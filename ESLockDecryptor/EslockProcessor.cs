using System.Reflection;
using ESLockDecryptor.Services;

namespace ESLockDecryptor;

public static class EslockProcessor
{
    public static void Execute(Options options)
    {
        PrintInfo();
        
        string exeDirectory = Path.GetDirectoryName(Environment.ProcessPath) ?? Directory.GetCurrentDirectory();

        FileSystemInfo inputPath = options.InputPath ?? new DirectoryInfo(exeDirectory);
        DirectoryInfo outputPath = options.OutputPath ?? new DirectoryInfo(exeDirectory);

        if (options.ExtractKeyOnly)
        {
            switch (inputPath)
            {
                case FileInfo fileInfo:
                    EslockDecryptor.DecryptFile(fileInfo.FullName, string.Empty, options);
                    break;

                case DirectoryInfo dirInfo:
                    EslockDecryptor.DecryptDirectory(dirInfo.FullName, string.Empty, options);
                    break;
            }

            PrintStats();
            return;
        }

        if (options.OutputPath is null)
        {
            string timestamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");

            string baseDir = inputPath switch
            {
                FileInfo fileInfo => Path.GetDirectoryName(fileInfo.FullName) ?? Directory.GetCurrentDirectory(),
                DirectoryInfo dirInfo => (dirInfo.FullName == exeDirectory)
                    ? dirInfo.FullName
                    : dirInfo.FullName.TrimEnd(Path.DirectorySeparatorChar),
                _ => Directory.GetCurrentDirectory()
            };

            outputPath = new DirectoryInfo(Path.Combine(baseDir, $"decrypted-{timestamp}"));
        }

        if (!outputPath.Exists)
        {
            Directory.CreateDirectory(outputPath.FullName);
            Console.WriteLine($"Created output directory: {outputPath.FullName}");
        }


        switch (inputPath)
        {
            case FileInfo fileInfo:
                EslockDecryptor.DecryptFile(fileInfo.FullName, outputPath.FullName, options);
                break;

            case DirectoryInfo dirInfo:
                EslockDecryptor.DecryptDirectory(dirInfo.FullName, outputPath.FullName, options);
                break;
        }

        PrintStats();
    }

    private static void PrintInfo()
    {
        Console.WriteLine("=======================================================================");
        Console.WriteLine("                            ESLockDecryptor");
        Console.WriteLine("=======================================================================");
        Console.WriteLine("Forensic tool for recovering ES File Explorer encrypted files (.eslock)");
        Console.WriteLine("                         ! FOR LEGAL USE ONLY !");
        Console.WriteLine($"            Version {Version} | (C) 2025 Piotr Kniaz | MIT License");
        Console.WriteLine("=======================================================================");
    }

    private static void PrintStats()
    {
        Console.WriteLine("\n=======================================================================");
        Console.WriteLine("Processing complete.");
        Console.WriteLine($"  Files processed:  {EslockDecryptor.FilesProcessed}");
        Console.WriteLine($"  Files decrypted:  {EslockDecryptor.FilesDecrypted}");
        Console.WriteLine($"  Files skipped:    {EslockDecryptor.FilesSkipped}");
        Console.WriteLine($"  Warnings:         {EslockDecryptor.Warnings}");
        Console.WriteLine($"  Errors:           {EslockDecryptor.Errors}");
        Console.WriteLine("=======================================================================");
    }

    public static readonly string Version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(2) ?? "---";
}