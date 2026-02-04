using ESLockDecryptor.Models;

namespace ESLockDecryptor.IO;

public interface IFooterReader
{
    EslockFooter ReadFooter(string filePath);
}