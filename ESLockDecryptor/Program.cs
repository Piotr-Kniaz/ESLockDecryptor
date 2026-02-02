using System.CommandLine;
using ESLockDecryptor.Models;
using ESLockDecryptor.Services;

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

var ignoreCrcOption = new Option<bool>(name: "--ignore-crc")
{
    Description = "Try to process even if the footer CRC check fails."
};

var readOnlyOption = new Option<bool>(name: "--read-only")
{
    Description = "Only read and print metadata (no decryption)."
};

var verboseOption = new Option<bool>(name: "--verbose", aliases: ["-v"])
{
    Description = "Enable detailed logging."
};

var overwriteOption = new Option<bool>(name: "--overwrite")
{
    Description = "Overwrite existing decrypted files."
};

var passwordOption = new Option<string>(name: "--password", aliases: ["-p"])
{
    Description = "Password for decryption."
};

var keyOption = new Option<string>(name: "--key", aliases: ["-k"])
{
    Description = "Hexadecimal key for decryption."
};

var heuristicOption = new Option<bool>(name: "--heuristic")
{
    Description = "Enable heuristic footer detection for files with corrupted or missing footers."
};

var rawDecryptOption = new Option<RawDecryptOptions?>(name: "--raw-decrypt")
{
    Description = "Enables raw decryption. Ignore metadata.",
    HelpName = "auto|full|partial[:size]",
    Arity = ArgumentArity.ZeroOrOne
};

#endregion

#region Parsers

rawDecryptOption.CustomParser = result =>
{
    // RawDecryptMode mode;

    if (result.Tokens.Count == 0)
    {
        return new RawDecryptOptions(RawDecryptMode.Auto);
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

        return new RawDecryptOptions(RawDecryptMode.Partial, size);
    }

    return new RawDecryptOptions((RawDecryptMode)mode);
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
        ReadOnly: parseResult.GetValue(readOnlyOption),
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

partial class Program
{
    [System.Text.RegularExpressions.GeneratedRegex(@"\A\b[0-9a-fA-F]+\b\Z")]
    private static partial System.Text.RegularExpressions.Regex HexRegex();
}