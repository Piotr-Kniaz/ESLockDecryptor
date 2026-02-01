using ESLockDecryptor.Models;

namespace ESLockDecryptor.Interfaces;

public interface IFooterReader
{
    EslockFooter? ReadFooter(string filePath);
}