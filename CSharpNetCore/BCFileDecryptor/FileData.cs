using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Text.Json;
using static System.Buffer;

namespace BCFileDecryptorCore
{
    class FileData
    {
        private class HeaderData
        {
            public int rawLen = 48; // always 48 bytes
            public int coreLen;
            public int corePaddingLen;
            public int ciipherPaddingLen;
        }

        public string EncryptedFileKey { get; private set; }
        public string OutputFilePath { get; private set; }
        public string EncryptedFilePath { get; private set; }
        public string BaseIVec { get; private set; }
        public int BlockSize { get; private set; }
        public int HeaderLen => headerData.rawLen + headerData.coreLen + headerData.corePaddingLen;
        public int CipherPadding { get { return headerData.ciipherPaddingLen; } }

        private readonly HeaderData headerData;

        // The following byte sequence corresponds to bc01; 
        // Note: There is another file version for bc02 now.
        private readonly byte[] supportedFileVersion = { (byte)98, (byte)99, (byte)48, (byte)49 };   

        // appends an incrementing number to either the output path
        // or the original path if no output was given until
        // a path is found for which no file exists yet
        // CAUTION: this can break if file names are too long
        private string CheckOutputFilePath(string currentPath)
        {
            int postFix = 1;
            string newPath = currentPath;
            string originalPath = currentPath;
            bool suitablePathFound = false;

            while (!suitablePathFound)
            {
                if (newPath.Length == 0)
                {
                    Console.WriteLine("Output filepath is empty, deriving it from input");

                    // first, get rid of the .bc extension
                    int startPos = 0;
                    int endPos = EncryptedFilePath.LastIndexOf(".");
                    if (endPos == -1)
                    {
                        break;
                    }
                    newPath = originalPath = EncryptedFilePath.Substring(startPos, endPos);
                }

                if (File.Exists(Path.Combine(newPath)))
                {
                    Console.WriteLine($"Output filepath '{newPath}' already exists, deriving a new one");

                    // insert a number after the file name
                    int extenstionPos = originalPath.LastIndexOf(".");
                    if (extenstionPos == -1)
                    {
                        break;
                    }

                    newPath = $"{originalPath.Substring(0, extenstionPos)} ({postFix}){originalPath.Substring(extenstionPos)}";
                    ++postFix;
                }
                else
                {
                    suitablePathFound = true;
                    break;
                }

                Console.WriteLine($"New output filepath: {newPath}");
            }

            if (!suitablePathFound)
            {
                throw new Exception("Could not find a usable output filepath");
            }

            return newPath;
        }

        public FileData()
        {
            headerData = new HeaderData();
        }

        public void ParseHeader(string encryptedFilePath, string outputFilePath)
        {
            Console.WriteLine($"Parsing header of encrypted file: '{encryptedFilePath}'");

            if (!encryptedFilePath.EndsWith(".bc"))
            {
                throw new Exception("Given filepath does not have the right extension ('.bc'), please specify a Boxcryptor encrypted file");
            }

            // Check if file is a regular file
            // Note: Possibly more FileAttributes other than 'Normal' and 'Archive' should be allowed
            FileAttributes attributes = File.GetAttributes(encryptedFilePath);
            if (attributes != FileAttributes.Normal && attributes != FileAttributes.Archive)
            {
                throw new Exception($"Encrypted file ({encryptedFilePath}) can't be opened (make sure the provided path "
                        + "is correct, the file exists and you have the right to open the file)");
            }

            EncryptedFilePath = encryptedFilePath;

            try
            {
                // read the first 16 bytes which contain the file version
                // and information about the length of the different file parts
                byte[] rawHeaderBytes = new byte[16];
                using FileStream fs = new FileStream(encryptedFilePath, FileMode.Open);
                fs.Read(rawHeaderBytes, 0, 16);

                byte[] fileVersionBytes = new byte[4];
                BlockCopy(rawHeaderBytes, 0, fileVersionBytes, 0, 4);
                if (!fileVersionBytes.SequenceEqual<byte>(supportedFileVersion))
                {
                    throw new Exception("Unknown file version found in header, aborting ...");
                }

                byte[] headerCoreLenBytes = new byte[4];
                BlockCopy(rawHeaderBytes, 4, headerCoreLenBytes, 0, 4);
                byte[] headerPaddingLenBytes = new byte[4];
                BlockCopy(rawHeaderBytes, 8, headerPaddingLenBytes, 0, 4);
                byte[] cipherPaddingLenBytes = new byte[4];
                BlockCopy(rawHeaderBytes, 12, cipherPaddingLenBytes, 0, 4);

                int headerCoreLen = (headerCoreLenBytes[3] & 0xFF) << 24 | (headerCoreLenBytes[2] & 0xFF) << 16
                        | (headerCoreLenBytes[1] & 0xFF) << 8 | (headerCoreLenBytes[0] & 0xFF);
                int headerPaddingLen = (headerPaddingLenBytes[3] & 0xFF) << 24 | (headerPaddingLenBytes[2] & 0xFF) << 16
                        | (headerPaddingLenBytes[1] & 0xFF) << 8 | (headerPaddingLenBytes[0] & 0xFF);
                int cipherPaddingLen = (cipherPaddingLenBytes[3] & 0xFF) << 24 | (cipherPaddingLenBytes[2] & 0xFF) << 16
                        | (cipherPaddingLenBytes[1] & 0xFF) << 8 | (cipherPaddingLenBytes[0] & 0xFF);

                headerData.coreLen = headerCoreLen;
                headerData.corePaddingLen = headerPaddingLen;
                headerData.ciipherPaddingLen = cipherPaddingLen;

                // go to the end of the raw header and read the core header
                fs.Seek(headerData.rawLen - 16, SeekOrigin.Current);
                byte[] coreHeaderBytes = new byte[headerData.coreLen];
                fs.Read(coreHeaderBytes, 0, headerData.coreLen);

                // Parsing JSON using Microsoft Json library
                string coreHeaderString = Encoding.Default.GetString(coreHeaderBytes);
                JsonDocument doc = JsonDocument.Parse(coreHeaderString);
                JsonElement root = doc.RootElement;
                JsonElement cipherInfo = root.GetProperty("cipher");
                BlockSize = cipherInfo.GetProperty("blockSize").GetInt32();
                BaseIVec = cipherInfo.GetProperty("iv").GetString();
                JsonElement fileKeyInfo = root.GetProperty("encryptedFileKeys");
                JsonElement.ArrayEnumerator fileKeyArray = fileKeyInfo.EnumerateArray();
                List<JsonElement> fileKeyList = fileKeyArray.ToList<JsonElement>();
                EncryptedFileKey = fileKeyList[0].GetProperty("value").GetString();
                OutputFilePath = CheckOutputFilePath(outputFilePath);
            }
            catch (Exception e)
            {
                if (e is IOException || e is JsonException || e is KeyNotFoundException 
                    || e is InvalidOperationException || e is ArgumentNullException
                    || e is DecoderFallbackException) {
                    throw new Exception("Header could not be parsed", e);
                }
                throw;
            }

            Console.WriteLine("Parsing finished");
        }
    }
}
