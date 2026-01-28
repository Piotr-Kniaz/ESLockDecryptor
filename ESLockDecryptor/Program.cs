using System.CommandLine;
using System.CommandLine.Parsing;
// using System.Reflection;

namespace ESLockDecryptor;

public record ProgramOptions(
    FileSystemInfo InputPath,
    string? OutputPath,
    bool ExtractKeyOnly,
    bool IgnoreCrc,
    bool Verbose,
    bool Overwrite,
    string? Password,
    string? Key
);


class Program
{
    static int Main(string[] args)
    {
        // var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(2);

        var inputArgument = new Argument<string?>("input")
        {
            Description = "Path to input file or directory. Defaults to current directory if omitted.",
            Arity = ArgumentArity.ZeroOrOne
        };

        var outputArgument = new Argument<string?>("output")
        {
            Description = "Destination directory. If omitted, a timestamped 'decrypted-YYYYMMDD-HHMMSS' folder will be "
            + "created alongside the input.",
            Arity = ArgumentArity.ZeroOrOne
        };

        var extractKeyOption = new Option<bool>(name: "--extract-key")
        {
            Description = "Only read metadata and print encryption keys (no decryption)."
        };

        var ignoreCrcOption = new Option<bool>(name: "--ignore-crc")
        {
            Description = "Try to process even if the footer CRC check fails."
        };

        var verboseOption = new Option<bool>(name: "--verbose", aliases: ["-v"])
        {
            Description = "Enable detailed logging."
        };

        var overwriteOption = new Option<bool>(name: "--force", aliases: ["-f"])
        {
            Description = "Overwrite existing files without asking."
        };

        var passwordOption = new Option<string?>(name: "--password", aliases: ["-p"])
        {
            Description = "Password for decryption."
        };

        var keyOption = new Option<string?>(name: "--key", aliases: ["-k"])
        {
            Description = "Hexadecimal key for decryption."
        };

        var rootCommand = new RootCommand("Forensic utility for recovering ES File Explorer files")
        {
            inputArgument,
            outputArgument,
            // overwriteOption,
            ignoreCrcOption,
            verboseOption,
            passwordOption,
            keyOption,
            extractKeyOption,
        };

        ParseResult parseResult = rootCommand.Parse(args);

        if (parseResult.Errors.Count == 0)
        {
            Console.WriteLine(parseResult.GetValue<string>("--password"));
            return parseResult.Invoke();
        }
        foreach (ParseError parseError in parseResult.Errors)
        {
            Console.Error.WriteLine(parseError.Message);
        }
        return 1;

        // var parser = new CommandLineBuilder(rootCommand)
        //     .UseDefaults()
        //     .UseExceptionHandler((e, context) =>
        //     {
        //         Console.ForegroundColor = ConsoleColor.Red;
        //         Console.Error.WriteLine($"[CRITICAL ERROR] {e.Message}");
        //         Console.ResetColor();
        //         context.ExitCode = 1;
        //     })
        //     .Build();

        // return await parser.InvokeAsync(args);



        // Console.WriteLine("=======================================================");
        // Console.WriteLine("Utility for recovering ES File Explorer files (.eslock)");
        // Console.WriteLine("                ! FOR LEGAL USE ONLY !");
        // Console.WriteLine($"   Version {version} | (C) 2025 Piotr Kniaz | MIT License");
        // Console.WriteLine("=======================================================");

        // if (args.Length > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "/?"))
        // {
        //     PrintUsage();
        //     return 0;
        // }


        // string inputPath;
        // string? outputPath = null;

        // string exePath = Environment.ProcessPath ?? string.Empty;
        // string exeDirectory = Path.GetDirectoryName(exePath) ?? Directory.GetCurrentDirectory();

        // try
        // {
        //     if (args.Length == 0)
        //     {
        //         inputPath = exeDirectory;
        //         Console.WriteLine("No arguments provided. Using current directory as input.");
        //     }
        //     else if (args.Length == 1)
        //     {
        //         inputPath = args[0];
        //     }
        //     else
        //     {
        //         inputPath = args[0];
        //         outputPath = args[1];
        //     }

        //     inputPath = Path.GetFullPath(inputPath);

        //     if (!File.Exists(inputPath) && !Directory.Exists(inputPath))
        //     {
        //         Console.WriteLine($"[ERROR] Input path does not exist: {inputPath}");
        //         PrintUsage();
        //         return 1;
        //     }

        //     if (string.IsNullOrEmpty(outputPath))
        //     {
        //         string timestamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        //         string baseDir = File.Exists(inputPath)
        //             ? Path.GetDirectoryName(inputPath) ?? exeDirectory
        //             : inputPath;
                
        //         outputPath = Path.Combine(baseDir, $"decrypted-{timestamp}");
        //     }

        //     outputPath = Path.GetFullPath(outputPath);

        //     if (!Directory.Exists(outputPath))
        //     {
        //         Directory.CreateDirectory(outputPath);
        //         Console.WriteLine($"Created output directory: {outputPath}");
        //     }

        //     if (Directory.Exists(inputPath))
        //     {
        //         Console.WriteLine($"Processing directory: {inputPath}");
        //         EslockDecryptor.DecryptDirectory(inputPath, outputPath);
        //     }
        //     else
        //     {
        //         Console.WriteLine($"Processing file: {inputPath}");
        //         EslockDecryptor.DecryptFile(inputPath, outputPath);
        //     }

        //     Console.WriteLine();
        //     Console.WriteLine("Done.");
        //     return 0;
        // }
        // catch (Exception ex)
        // {
        //     Console.WriteLine($"[FATAL ERROR] {ex.Message}");
        //     return 1;
        // }

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