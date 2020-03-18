using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Text.Json;

namespace BCFileDecryptorCore
{
    class FileData
    {
        // NOTE: This class is static in Java code. 
        // It cannot be static here, since it is instantiated later
        private class HeaderData
        {
            public int rawLen = 48; // always 48 bytes
            public int coreLen;
            public int corePaddingLen;
            public int ciipherPaddingLen;
        }

        private string encryptedFileKey;
        private string baseIVec;
        private string encryptedFilePath;
        private int blockSize;
        private HeaderData headerData;
        private string outputFilePath;
        private byte[] supportedFileVersion = { (byte)98, (byte)99, (byte)48, (byte)49 };

        // appends a incrementing number to either the output path
        // or the original path if no output was given until
        // a path is found for which no file exists yet
        // CAUTION: this can break if file names are too long
        private string checkOutputFilePath(string currentPath)
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
                    int endPos = this.encryptedFilePath.LastIndexOf(".");
                    if (endPos == -1)
                    {
                        break;
                    }
                    newPath = originalPath = this.encryptedFilePath.Substring(startPos, endPos);
                }

                if (File.Exists(Path.Combine(newPath)))
                {
                    Console.WriteLine("Output filepath '" + newPath + "' already exists, deriving a new one");

                    // insert a number after the file name
                    int extenstionPos = originalPath.LastIndexOf(".");
                    if (extenstionPos == -1)
                    {
                        break;
                    }

                    newPath = originalPath.Substring(0, extenstionPos) + " (" + postFix + ")" + originalPath.Substring(extenstionPos);
                    ++postFix;
                }
                else
                {
                    suitablePathFound = true;
                    break;
                }

                Console.WriteLine("New output filepath: " + newPath);
            }

            if (!suitablePathFound)
            {
                throw new SystemException("Could not find a usable output filepath");
            }

            return newPath;
        }

        public FileData()
        {
            this.headerData = new HeaderData();
        }

        public void parseHeader(string encryptedFilePath, string outputFilePath)
        {
            Console.WriteLine("Parsing header of encrypted file: '" + encryptedFilePath + "'");

            if (!encryptedFilePath.Substring(encryptedFilePath.Length - 3).Equals(".bc"))
            {
                throw new SystemException("Given filepath does not have the right extension ('.bc'), please specify a Boxcryptor encrypted file");
            }

            // Check if file is a regular file
            // Note: Possibly more FileAttributes other than 'Normal' and 'Archive' should be allowed
            FileAttributes attributes = File.GetAttributes(encryptedFilePath);
            if (attributes != FileAttributes.Normal && attributes != FileAttributes.Archive)
            {
                throw new SystemException("Encrypted file (" + encryptedFilePath + ") can't be opened (make sure the provided path "
                        + "is correct, the file exists and you have the right to open the file)");
            }

            this.encryptedFilePath = encryptedFilePath;

            try
            {
                // read the first 16 bytes which contain the file version
                // and information about the length of the different file parts
                byte[] rawHeaderBytes = new byte[16];
                using (FileStream fs = new FileStream(encryptedFilePath, FileMode.Open))       
                {
                    fs.Read(rawHeaderBytes, 0, 16);

                    byte[] fileVersionBytes = new byte[4];
                    System.Buffer.BlockCopy(rawHeaderBytes, 0, fileVersionBytes, 0, 4);
                    if (!fileVersionBytes.SequenceEqual<byte>(this.supportedFileVersion))
                    {
                        throw new SystemException("Unknown file version found in header, aborting ...");
                    }

                    byte[] headerCoreLenBytes = new byte[4];
                    System.Buffer.BlockCopy(rawHeaderBytes, 4, headerCoreLenBytes, 0, 4);
                    byte[] headerPaddingLenBytes = new byte[4];
                    System.Buffer.BlockCopy(rawHeaderBytes, 8, headerPaddingLenBytes, 0, 4);
                    byte[] cipherPaddingLenBytes = new byte[4];
                    System.Buffer.BlockCopy(rawHeaderBytes, 12, cipherPaddingLenBytes, 0, 4);

                    int headerCoreLen = (headerCoreLenBytes[3] & 0xFF) << 24 | (headerCoreLenBytes[2] & 0xFF) << 16
                            | (headerCoreLenBytes[1] & 0xFF) << 8 | (headerCoreLenBytes[0] & 0xFF);
                    int headerPaddingLen = (headerPaddingLenBytes[3] & 0xFF) << 24 | (headerPaddingLenBytes[2] & 0xFF) << 16
                            | (headerPaddingLenBytes[1] & 0xFF) << 8 | (headerPaddingLenBytes[0] & 0xFF);
                    int cipherPaddingLen = (cipherPaddingLenBytes[3] & 0xFF) << 24 | (cipherPaddingLenBytes[2] & 0xFF) << 16
                            | (cipherPaddingLenBytes[1] & 0xFF) << 8 | (cipherPaddingLenBytes[0] & 0xFF);

                    this.headerData.coreLen = headerCoreLen;
                    this.headerData.corePaddingLen = headerPaddingLen;
                    this.headerData.ciipherPaddingLen = cipherPaddingLen;

                    // go to the end of the raw header and read the core header
                    fs.Seek(this.headerData.rawLen - 16, SeekOrigin.Current);
                    byte[] coreHeaderBytes = new byte[this.headerData.coreLen];
                    fs.Read(coreHeaderBytes, 0, this.headerData.coreLen);

                    // Parsing JSON using Microsoft Json library
                    string coreHeaderString = Encoding.Default.GetString(coreHeaderBytes);
                    JsonDocument doc = JsonDocument.Parse(coreHeaderString);
                    JsonElement root = doc.RootElement;
                    JsonElement cipherInfo = root.GetProperty("cipher");
                    this.blockSize = cipherInfo.GetProperty("blockSize").GetInt32();
                    this.baseIVec = cipherInfo.GetProperty("iv").GetString();
                    JsonElement fileKeyInfo = root.GetProperty("encryptedFileKeys");
                    JsonElement.ArrayEnumerator fileKeyArray = fileKeyInfo.EnumerateArray();
                    List<JsonElement> fileKeyList = fileKeyArray.ToList<JsonElement>();
                    this.encryptedFileKey = fileKeyList[0].GetProperty("value").GetString();
                    this.outputFilePath = this.checkOutputFilePath(outputFilePath);
                }
            }
            catch (Exception e)
            {
                if (e is IOException || e is JsonException || e is KeyNotFoundException 
                    || e is InvalidOperationException || e is ArgumentNullException
                    || e is DecoderFallbackException) {
                    throw new SystemException("Header could not be parsed", e);
                }
            }

            Console.WriteLine("Parsing finished");
        }

        public string getOutputFilePath()
        {
            return this.outputFilePath;
        }

        public string getEncryptedFileKey()
        {
            return this.encryptedFileKey;
        }

        public string getEncryptedFilePath()
        {
            return this.encryptedFilePath;
        }

        public string getBaseIVec()
        {
            return this.baseIVec;
        }

        public int getBlockSize()
        {
            return this.blockSize;
        }

        public int getHeaderLen()
        {
            return this.headerData.rawLen + this.headerData.coreLen + this.headerData.corePaddingLen;
        }

        public int getCipherPadding()
        {
            return this.headerData.ciipherPaddingLen;
        }
    }
}
