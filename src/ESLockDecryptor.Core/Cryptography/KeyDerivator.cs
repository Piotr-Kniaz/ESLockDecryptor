using System.Security.Cryptography;
using System.Text;

namespace ESLockDecryptor.Core.Cryptography;

public static class KeyDerivator
{
    public static byte[] DeriveKeyFromPassword(string password) =>
        [.. MD5.HashData(Encoding.UTF8.GetBytes(password)).Take(16)];
}