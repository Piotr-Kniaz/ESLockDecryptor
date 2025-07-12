namespace ESLockDecryptor;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Utility for decrypting ES File Explorer files (.eslock)");
        Console.WriteLine("                ! FOR LEGAL USE ONLY !");
        Console.WriteLine("   Version 1.0 | (C) 2025 Piotr Kniaz | MIT License");
        Console.WriteLine("=======================================================");

        if (args.Length < 2)
        {
            PrintUsage();
            return;
        }

        string inputPath = args[0];
        string outputPath = args[1];

        // For debugging
        // string inputPath = "encrypted";
        // string outputPath = "decrypted";

        if (!Directory.Exists(outputPath))
        {
            Directory.CreateDirectory(outputPath);
        }

        if (Directory.Exists(inputPath))
        {
            EslockDecryptor.DecryptDirectory(inputPath, outputPath);
        }
        else if (File.Exists(inputPath))
        {
            EslockDecryptor.DecryptFile(inputPath, outputPath);
        }
        else
        {
            Console.WriteLine($"[ERROR] The path is not exists: {inputPath}");
        }
    }

    static void PrintUsage()
    {
        Console.WriteLine("Using:");
        Console.WriteLine("  For the file:");
        Console.WriteLine("    ./ESLockDecryptor \"path/to/file.eslock\" \"path/to/output/directory\"");
        Console.WriteLine("  For directory:");
        Console.WriteLine("    ./ESLockDecryptor \"path/to/input/direcrory\" \"path/to/output/directory\"");
    }
}