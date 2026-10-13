using System.Security.Cryptography;
using System.Text;

namespace ESLockDecryptor.Core.Cryptography;

/// <summary>Derives keys from a passwords.</summary>
public static class KeyDerivator
{
    /// <summary>Derives a 16-byte AES key from a password using MD5 over UTF-8 bytes.</summary>
    /// <param name="password">The password to derive from.</param>
    /// <returns>The derived 16-byte key.</returns>
    public static byte[] DeriveKeyFromPassword(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        return [.. MD5.HashData(Encoding.UTF8.GetBytes(password)).Take(16)];
    }
}