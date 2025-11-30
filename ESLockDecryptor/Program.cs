using System.Reflection;

namespace ESLockDecryptor;

class Program
{
    static int Main(string[] args)
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(2);

        Console.WriteLine("=======================================================");
        Console.WriteLine("Utility for recovering ES File Explorer files (.eslock)");
        Console.WriteLine("                ! FOR LEGAL USE ONLY !");
        Console.WriteLine($"   Version {version} | (C) 2025 Piotr Kniaz | MIT License");
        Console.WriteLine("=======================================================");

        if (args.Length > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "/?"))
        {
            PrintUsage();
            return 0;
        }


        string inputPath;
        string? outputPath = null;

        string exePath = Environment.ProcessPath ?? string.Empty;
        string exeDirectory = Path.GetDirectoryName(exePath) ?? Directory.GetCurrentDirectory();

        try
        {
            if (args.Length == 0)
            {
                inputPath = exeDirectory;
                Console.WriteLine("No arguments provided. Using current directory as input.");
            }
            else if (args.Length == 1)
            {
                inputPath = args[0];
            }
            else
            {
                inputPath = args[0];
                outputPath = args[1];
            }

            inputPath = Path.GetFullPath(inputPath);

            if (!File.Exists(inputPath) && !Directory.Exists(inputPath))
            {
                Console.WriteLine($"[ERROR] Input path does not exist: {inputPath}");
                PrintUsage();
                return 1;
            }

            if (string.IsNullOrEmpty(outputPath))
            {
                string timestamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
                string baseDir = File.Exists(inputPath)
                    ? Path.GetDirectoryName(inputPath) ?? exeDirectory
                    : inputPath;
                
                outputPath = Path.Combine(baseDir, $"decrypted-{timestamp}");
            }

            outputPath = Path.GetFullPath(outputPath);

            if (!Directory.Exists(outputPath))
            {
                Directory.CreateDirectory(outputPath);
                Console.WriteLine($"Created output directory: {outputPath}");
            }

            if (Directory.Exists(inputPath))
            {
                Console.WriteLine($"Processing directory: {inputPath}");
                EslockDecryptor.DecryptDirectory(inputPath, outputPath);
            }
            else
            {
                Console.WriteLine($"Processing file: {inputPath}");
                EslockDecryptor.DecryptFile(inputPath, outputPath);
            }

            Console.WriteLine();
            Console.WriteLine("Done.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[FATAL ERROR] {ex.Message}");
            return 1;
        }

    }

    static void PrintUsage()
    {
        Console.WriteLine("Usage:");
        Console.WriteLine("    ESLockDecryptor [input_path] [output_path]");
        Console.WriteLine("\nScenarios:");
        Console.WriteLine("1. Auto-mode (current folder):");
        Console.WriteLine("    ./ESLockDecryptor");
        Console.WriteLine("2. Input specified, auto-output:");
        Console.WriteLine("    ./ESLockDecryptor \"path/to/encrypted_file_or_directory\"");
        Console.WriteLine("3. Explicit input and output:");
        Console.WriteLine("    ./ESLockDecryptor \"encrypted/path\" \"decrypted/path\"");
    }
}