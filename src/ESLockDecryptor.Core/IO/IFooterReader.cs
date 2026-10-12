using ESLockDecryptor.Core.Models;

namespace ESLockDecryptor.Core.IO;

public interface IFooterReader
{
    EslockFooter? ReadFooter(string filePath);
}