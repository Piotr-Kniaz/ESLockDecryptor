namespace ESLockDecryptor.Extensions;

public static class StreamExtensions
{
    public static void CopyTo(this Stream source, Stream destination, long count)
    {
        byte[] buffer = new byte[81920];
        long bytesCopied = 0;

        while (bytesCopied < count)
        {
            int bytesToRead = (int)Math.Min(buffer.Length, count - bytesCopied);
            int bytesRead = source.Read(buffer, 0, bytesToRead);

            if (bytesRead == 0)
                break;

            destination.Write(buffer, 0, bytesRead);
            bytesCopied += bytesRead;
        }
    }
}