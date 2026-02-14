# How to use ESLockDecryptor

In most cases, the basic mode of ESLockDecryptor is sufficient:

```bash
./ESLockDecryptor "file.eslock" "decrypted-directory"
```

If you see `[ERROR] CRC check failed`, the footer may be corrupted. CRC is a checksum of the key, encryption type, and the original file name. You can try to decrypt the file by bypassing the CRC check:

```bash
./ESLockDecryptor "corrupted-file.eslock" "." --ignore-crc
```

If the key was indeed corrupted, you will receive an incorrectly decrypted file. In this case you can use **`--password`** (if known) or **`--key`**:

```bash
./ESLockDecryptor "corrupted-file.eslock" "." -p "12345678"
```

The key can be obtained from a valid file using **`--read-only`** or **`--verbose`** (during decryption). If you're decrypting a directory with a large number of files, they will likely have the same keys.

```bash
# Print metadata
./ESLockDecryptor --read-only "valid-file.eslock"

# Using obtained key (hexadecimal string)
./ESLockDecryptor "corrupted-file.eslock" "." -k "25D55AD283AA400AF464C76D713C07AD"
```

Even this way, you may end up with an incorrectly decrypted file. In that case, follow the instructions below.

If you see `[ERROR] Incorrect footer length` you can try another way to search footer and parse metadata:

```bash
./ESLockDecryptor "corrupted-file.eslock" "." --heuristic
```

In some cases, it may be necessary to use multiple flags, for example:

```bash
./ESLockDecryptor "corrupted-file.eslock" "." --heuristic --ignore-crc
# or
./ESLockDecryptor "corrupted-file.eslock" "." --heuristic -p "12345678"
```

If the file does contain a corrupted footer, **`--raw-decrypt --heuristic`** can find and trim it, and decrypt the file with default parameters (key or password is required):

```bash
./ESLockDecryptor "corrupted-file.eslock" "." --heuristic --raw-decrypt -p "12345678"
```

If the above steps do not produce a satisfactory result (footer is not found or the decrypted file is invalid), then most likely the file is truncated. In this case, you can try to partially recover the file using **`--raw-decrypt`** (key or password is required) without **`--heuristic`**:

```bash
./ESLockDecryptor "truncated-file.eslock" "." --raw-decrypt -k "25D55AD283AA400AF464C76D713C07AD"
```

In this case, metadata is completely ignored (considered truncated) and default parameters ​​are used. If **`--raw-decrypt`** succeeds, additional file recovery steps may be required.