using System.CommandLine;
using ESLockDecryptor.Services;

string description = "ESLockDecryptor is a forensic tool for recovering ES File Explorer encrypted files (.eslock)";

#region Arguments and Options

var inputArgument = new Argument<FileSystemInfo>("input")
{
    Description = "Path to input file or directory. Defaults to current directory if omitted.",
    Arity = ArgumentArity.ZeroOrOne
}
.AcceptLegalFilePathsOnly()
.AcceptExistingOnly();

var outputArgument = new Argument<DirectoryInfo?>("output")
{
    Description = "Destination directory. If omitted, a timestamped folder will be created alongside the input.",
    Arity = ArgumentArity.ZeroOrOne
}
.AcceptLegalFilePathsOnly();

var ignoreCrcOption = new Option<bool>(name: "--ignore-crc")
{
    Description = "Try to process even if the footer CRC check fails."
};

var extractKeyOption = new Option<bool>(name: "--extract-key")
{
    Description = "Only read metadata and print encryption keys (no decryption)."
};

var verboseOption = new Option<bool>(name: "--verbose", aliases: ["-v"])
{
    Description = "Enable detailed logging."
};

var overwriteOption = new Option<bool>(name: "--overwrite")
{
    Description = "Overwrite existing decrypted files."
};

var passwordOption = new Option<string?>(name: "--password", aliases: ["-p"])
{
    Description = "Password for decryption."
};

var keyOption = new Option<string?>(name: "--key", aliases: ["-k"])
{
    Description = "Hexadecimal key for decryption."
};

#endregion

var rootCommand = new RootCommand(description)
{
    inputArgument,
    outputArgument,
    ignoreCrcOption,
    overwriteOption,
    verboseOption,
    passwordOption,
    keyOption,
    extractKeyOption
};

#region Validators

keyOption.Validators.Add(result =>
{
    var key = result.GetValueOrDefault<string>();
    if (!string.IsNullOrEmpty(key))
    {
        if (key.Length != 32 || !HexRegex().IsMatch(key))
        {
            result.AddError("Key must be a 32-character hexadecimal string.");
        }
    }
});

rootCommand.Validators.Add(result =>
{
    bool hasKey = result.GetResult(keyOption) is not null;
    bool hasPass = result.GetResult(passwordOption) is not null;

    if (hasKey && hasPass)
    {
        result.AddError("You cannot specify both '--key' and '--password'. Please choose one.");
    }
});

#endregion

rootCommand.SetAction(parseResult =>
{
    var options = new Options(
        InputPath: parseResult.GetValue(inputArgument),
        OutputPath: parseResult.GetValue(outputArgument),
        ExtractKeyOnly: parseResult.GetValue(extractKeyOption),
        IgnoreCrc: parseResult.GetValue(ignoreCrcOption),
        Verbose: parseResult.GetValue(verboseOption),
        Overwrite: parseResult.GetValue(overwriteOption),
        Password: parseResult.GetValue(passwordOption),
        Key: parseResult.GetValue(keyOption)
    );

    ESLockDecryptor.EslockProcessor.Execute(options);
    return 0;
});

ParseResult parseResult = rootCommand.Parse(args);

return parseResult.Invoke();


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

// static void PrintUsage()
// {
//     Console.WriteLine("Usage:");
//     Console.WriteLine("    ESLockDecryptor [input_path] [output_path]");
//     Console.WriteLine("\nScenarios:");
//     Console.WriteLine("1. Auto-mode (current folder):");
//     Console.WriteLine("    ./ESLockDecryptor");
//     Console.WriteLine("2. Input specified, auto-output:");
//     Console.WriteLine("    ./ESLockDecryptor \"path/to/encrypted_file_or_directory\"");
//     Console.WriteLine("3. Explicit input and output:");
//     Console.WriteLine("    ./ESLockDecryptor \"encrypted/path\" \"decrypted/path\"");
// }

partial class Program
{
    [System.Text.RegularExpressions.GeneratedRegex(@"\A\b[0-9a-fA-F]+\b\Z")]
    private static partial System.Text.RegularExpressions.Regex HexRegex();
}