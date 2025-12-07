# ESLockDecryptor

**ESLockDecryptor** is a command-line utility designed to recover and decrypt files encrypted by ES File Explorer (files with the `.eslock` extension). It supports processing both individual files and entire directories.

> [!WARNING]
> **FOR LEGAL USE ONLY!** This tool is intended for recovering **your own** files to which you have lost access. The author is not responsible for any misuse of this software or for recovering files without the owner's permission.

## Features

*   **Batch Processing:** Decrypt entire directories containing `.eslock` files.
*   **Single File Mode:** Decrypt specific files.
*   **Auto-Detection:** Automatically detects input/output paths if not specified.
*   **Fast and Lightweight:** Simple CLI interface, parallel decryption of multiple files.

<p align="center"><img width="692" alt="Screenshot" src="https://github.com/user-attachments/assets/4e2ce6af-1511-429d-bd8d-cc36879adaa1"/></p>

## Downloads & Supported Platforms

You can download the latest pre-built binaries for your system from the **[Releases](../../releases)** page.

*No .NET Runtime installation required.*

**Supported Platforms:**
*   **Windows:** x64, x86, Arm64
*   **Linux:** x64, Arm64
    *(tested on Ubuntu & Fedora; compatible with Debian, Arch, Mint, openSUSE, and other glibc-based distributions)*
*   **macOS:** Arm64 (Apple Silicon), x64 (Intel)


## How to Run *(Important)*

**This is a Command Line Interface (CLI) tool.** It is meant to be executed from a terminal (Command Prompt, PowerShell, Bash).

**❌ Do not run by double-clicking:**
*   **Windows:** The terminal window will close immediately after the process finishes, preventing you from seeing the success/error logs.
*   **Linux:** The process may run in the background with no visual feedback, making it unclear if the decryption finished.

**✅ Correct way:**
1.  Open your terminal.
2.  Navigate to the folder containing the tool (`cd path/to/tool`).
3.  Run the command as shown below.


## Usage

```bash
ESLockDecryptor [input_path] [output_path]
```

### Output Directory Logic
If the `[output_path]` argument is omitted (Scenarios 1 & 2), the utility automatically creates a new directory in the current working location using the format:
`./decrypted-yyyyMMdd-hhmmss`
*(e.g., `decrypted-20251201-150000`)*


### Scenarios

#### 1. Auto-mode (Current Folder)
**Requirement:** Place the `ESLockDecryptor` executable **directly inside** the folder containing the encrypted `.eslock` files.
```bash
./ESLockDecryptor
```
*The tool will scan the current directory and save decrypted files to a new timestamped folder.*


#### 2. Specific Input (Auto-Output)
Specify the path to the directory containing encrypted files. The output folder (`decrypted-...`) will be created **inside the specified directory**.
```bash
./ESLockDecryptor "path/to/encrypted_directory"
```
*Result location: `path/to/encrypted_directory/decrypted-yyyyMMdd-hhmmss`*

#### 3. Explicit Input and Output
Specify exactly where to take files from and where to save the decrypted versions.
```bash
./ESLockDecryptor "encrypted/path" "decrypted/path"
```

## Building from Source

If you prefer to build the application yourself, ensure you have the **.NET 10 SDK** installed.

1.  Clone the repository:
    ```bash
    git clone https://github.com/Piotr-Kniaz/ESLockDecryptor.git
    cd ESLockDecryptor
    ```
2.  Build the project:
    ```bash
    dotnet build --configuration Release
    ```

## License

This project is licensed under the **MIT License**.
