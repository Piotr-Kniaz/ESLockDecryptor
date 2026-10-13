# ESLockDecryptor.Core

`ESLockDecryptor.Core` is a .NET library for reading metadata and decrypting
files created by ES File Explorer with the `.eslock` extension

## Installation

```bash
dotnet add package ESLockDecryptor.Core --version 1.0.0
```

The package currently targets `.NET 10`.

## Stream processing

`EslockFileDecryptor` contains the complete single-file workflow: footer
detection, key selection, CRC validation, original file name decryption, and
stream decryption. It does not open files or write logs.

```csharp
using ESLockDecryptor.Core.Configuration;
using ESLockDecryptor.Core.Processing;

var key = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
using Stream input = File.OpenRead("photo.jpg.eslock");

var options = new DecryptionOptions
{
    Key = key,
    Heuristic = false,
    IgnoreCrc = false
};

var plan = EslockFileDecryptor.Prepare(input, options);

Console.WriteLine(plan.OriginalFileName);

using Stream output = File.Create(plan.OriginalFileName ?? "photo.jpg");
EslockFileDecryptor.Decrypt(input, output, plan);
```

For a browser application, use a seekable stream such as `MemoryStream` when
the browser file stream itself does not support seeking.

## Low-level decryption

```csharp
using ESLockDecryptor.Core.Configuration;
using ESLockDecryptor.Core.Cryptography;

var key = KeyDerivator.DeriveKeyFromPassword("password");

using Stream input = File.OpenRead("photo.jpg.eslock");
using Stream output = File.Create("photo.jpg");

var config = DecryptionConfig.CreateFullEncryption(
    originalFileLength: input.Length,
    key: key);

EslockDecryptor.DecryptStream(input, output, config);
```

For partial encryption, use `CreatePartialEncryption` and provide the
encrypted block size:

```csharp
var config = DecryptionConfig.CreatePartialEncryption(
    originalFileLength: input.Length,
    key: key,
    encryptedBlockSize: 1024);
```

The key must be the 16-byte AES key used by the file. When a password is
available, `KeyDerivator` can derive the key expected by ES File Explorer:

```csharp
var key = KeyDerivator.DeriveKeyFromPassword(password);
```

## Reading metadata

Footer readers require a seekable stream and restore the stream position after
reading:

```csharp
using ESLockDecryptor.Core.IO;

var reader = new StandardFooterReader();
var footer = reader.ReadFooter(input);

Console.WriteLine(footer.IsCrcValid);
Console.WriteLine(footer.FooterOffset);
```

Use `HeuristicFooterReader` when the standard footer cannot be read.

## Legal notice

Use this library only for files and systems you own or are explicitly
authorized to investigate. The project is distributed under the MIT License.