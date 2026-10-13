using ESLockDecryptor.Core.Configuration;
using ESLockDecryptor.Core.Models;

namespace ESLockDecryptor.Core.Processing;

/// <summary>Contains the configuration and metadata for one decryption operation.</summary>
public sealed record DecryptionPlan(
    DecryptionConfig Configuration,
    EslockFooter? Footer,
    string? OriginalFileName);