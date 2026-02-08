using System.CommandLine;
using ESLockDecryptor.Processing;
using ESLockDecryptor.Configuration;

const string description = "ESLockDecryptor is a forensic tool for recovering ES File Explorer encrypted files (.eslock)";

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

var verboseOption = new Option<bool>(name: "--verbose", aliases: ["-v"])
{
    Description = "Enable detailed logging."
};

var overwriteOption = new Option<bool>(name: "--overwrite")
{
    Description = "Overwrite existing decrypted files."
};

var readOnlyOption = new Option<bool>(name: "--read-only")
{
    Description = "Only read and print metadata (no decryption)."
};

var ignoreCrcOption = new Option<bool>(name: "--ignore-crc")
{
    Description = "Try to process even if the footer CRC check fails."
};

var passwordOption = new Option<string>(name: "--password", aliases: ["-p"])
{
    Description = "Use provided password for decryption, ignore key from metadata."
};

var keyOption = new Option<string>(name: "--key", aliases: ["-k"])
{
    Description = "Use provided key (hexadecimal string) for decryption, ignore key from metadata."
};

var heuristicOption = new Option<bool>(name: "--heuristic")
{
    Description = "Enable heuristic footer detection."
};

var rawDecryptOption = new Option<RawDecryptConfig?>(name: "--raw-decrypt")
{
    Description = "Enable raw decryption. Ignore metadata.",
    HelpName = "auto|full|partial[:size]",
    Arity = ArgumentArity.ZeroOrOne
};

#endregion

#region Parsers

rawDecryptOption.CustomParser = result =>
{
    if (result.Tokens.Count == 0)
    {
        return new RawDecryptConfig(RawDecryptMode.Auto);
    }

    string? value = result.Tokens[0].Value;

    var parts = value.Split(':', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    RawDecryptMode? mode = parts[0].ToLower() switch
    {
        "auto" => RawDecryptMode.Auto,
        "full" => RawDecryptMode.Full,
        "partial" => RawDecryptMode.Partial,
        _ => null
    };

    if (mode is null)
    {
        result.AddError("Invalid value for '--raw-decrypt'. Allowed values are: auto, full, partial[:size].");
        return null;
    }

    if (mode != RawDecryptMode.Partial && parts.Length > 1)
    {
        result.AddError("Size can only be specified when mode is 'partial'.");
        return null;
    }

    if (mode == RawDecryptMode.Partial && parts.Length == 2)
    {
        if (!int.TryParse(parts[1], out int size) || size <= 0)
        {
            result.AddError("Invalid size for '--raw-decrypt partial'. Size must be a positive integer.");
            return null;
        }

        return new RawDecryptConfig((RawDecryptMode)mode, size);
    }

    return new RawDecryptConfig((RawDecryptMode)mode);
};

#endregion

var rootCommand = new RootCommand(description)
{
    inputArgument,
    outputArgument,
    verboseOption,
    overwriteOption,
    readOnlyOption,
    ignoreCrcOption,
    passwordOption,
    keyOption,
    heuristicOption,
    rawDecryptOption
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
    bool hasOutputPath = result.GetResult(outputArgument) is not null;
    bool hasKey = result.GetResult(keyOption) is not null;
    bool hasPassword = result.GetResult(passwordOption) is not null;
    bool enabledOverwrite = result.GetResult(overwriteOption) is not null;
    bool enabledReadOnly = result.GetResult(readOnlyOption) is not null;
    bool enabledRawDecrypt = result.GetResult(rawDecryptOption) is not null;

    if (enabledReadOnly && hasOutputPath)
    {
        result.AddError("The '--read-only' option cannot be used with an output path. " +
            "If you need to save the log to file, redirect the console output instead.");
    }

    if (enabledReadOnly && enabledOverwrite)
    {
        result.AddError("The '--read-only' and '--overwrite' options cannot be used together.");
    }

    if (enabledReadOnly && enabledRawDecrypt)
    {
        result.AddError("The '--read-only' and '--raw-decrypt' options cannot be used together.");
    }

    if (hasKey && hasPassword)
    {
        result.AddError("The '--key' and '--password' options cannot be used together. Please choose one.");
    }

    if (enabledRawDecrypt && !(hasKey || hasPassword))
    {
        result.AddError("When using '--raw-decrypt', either '--key' or '--password' must be specified.");
    }
});

#endregion

rootCommand.SetAction(parseResult =>
{
    bool isReadOnlyEnabled = parseResult.GetValue(readOnlyOption);
    string? key = parseResult.GetValue(keyOption);

    string exeDirectory = Path.GetDirectoryName(Environment.ProcessPath) ?? Directory.GetCurrentDirectory();

    FileSystemInfo inputPath = parseResult.GetValue(inputArgument) ?? new DirectoryInfo(exeDirectory);
    DirectoryInfo? outputPath = parseResult.GetValue(outputArgument);

    if (outputPath is null && !isReadOnlyEnabled)
    {
        string timestamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        string baseDir = inputPath switch
        {
            FileInfo fileInfo => Path.GetDirectoryName(fileInfo.FullName) ?? exeDirectory,
            DirectoryInfo dirInfo => (dirInfo.FullName == exeDirectory)
                ? dirInfo.FullName
                : dirInfo.Parent?.FullName ?? dirInfo.FullName,
            _ => Directory.GetCurrentDirectory()
        };
        outputPath = new DirectoryInfo(Path.Combine(baseDir, $"decrypted-{timestamp}"));
    }

    var config = new ProcessingConfig(
        InputPath: inputPath,
        OutputPath: outputPath,
        Verbose: parseResult.GetValue(verboseOption),
        Overwrite: parseResult.GetValue(overwriteOption),
        ReadOnly: parseResult.GetValue(readOnlyOption),
        IgnoreCrc: parseResult.GetValue(ignoreCrcOption),
        Password: parseResult.GetValue(passwordOption),
        Key: key is null ? null : Convert.FromHexString(key),
        Heuristic: parseResult.GetValue(heuristicOption),
        RawDecryptConfig: parseResult.GetValue(rawDecryptOption)
    );

    var processor = new EslockProcessor(config);
    processor.Execute();
    return 0;
});

ParseResult parseResult = rootCommand.Parse(args);

return parseResult.Invoke();

partial class Program
{
    [System.Text.RegularExpressions.GeneratedRegex(@"\A\b[0-9a-fA-F]+\b\Z")]
    private static partial System.Text.RegularExpressions.Regex HexRegex();
}