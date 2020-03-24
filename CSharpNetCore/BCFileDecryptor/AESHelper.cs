using System;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using static System.Buffer;

namespace BCFileDecryptorCore
{   
    public class UnsupportedEncodingException : Exception
    {
        // in .NET Framework application this exception inherits 
        // from System.IdentityModel.RequestException, which is 
        // unavailable in .NET Core
    }

    class AESHelper
    {
        private static byte[] ComputeBlockIVec(byte[] IVec, long seed, byte[] key)
        {
            if (IVec.Length <= 0 || key.Length <= 0)
            {
                throw new Exception("Base initialization vector and crypto key can't be empty");
            }

            byte[] md = new byte[8];
            for (int i = 0; i < 8; ++i)
            {
                md[i] = (byte)(seed & 0xff);
                seed >>= 8;
            }

            byte[] data = new byte[IVec.Length + md.Length];
            BlockCopy(IVec, 0, data, 0, IVec.Length);
            BlockCopy(md, 0, data, IVec.Length, md.Length);

            byte[] buffer = HashHelper.ComputeSHA256HMAC(data, key, true);
            byte[] result = new byte[IVec.Length];
            Array.Copy(buffer, 0, result, 0, IVec.Length);

            return result;
        }

        public static byte[] DecryptData(byte[] data, byte[] cryptoKey, byte[] IVec)
        {
            return DecryptData(data, cryptoKey, IVec, PaddingMode.PKCS7);
        }
        public static byte[] DecryptData(byte[] data, byte[] cryptoKey, byte[] IVec, PaddingMode padding)
        {
            if (data.Length < 0 || cryptoKey.Length <= 0 || IVec.Length <= 0)
            {
                throw new Exception("Encrypted data, crypto key and initialization vector can't be empty");
            }

            byte[] result;
            try
            {
                // PKCS7 padding (https://en.wikipedia.org/wiki/PKCS) is used in case the
                // last data block is smaller than the block size used by AES (16 bytes)
                using Aes aes = Aes.Create();
                aes.Mode = CipherMode.CBC;
                aes.Key = cryptoKey;
                aes.IV = IVec;
                aes.Padding = padding;
                ICryptoTransform decryptor = aes.CreateDecryptor();
                using MemoryStream mStream = new MemoryStream();
                using CryptoStream cStream = new CryptoStream(mStream, decryptor, CryptoStreamMode.Write);
                cStream.Write(data, 0, data.Length);
                cStream.FlushFinalBlock();
                result = mStream.ToArray();

            }
            catch (ArgumentException e) 
            {
                throw new Exception("Data could not be decrypted", e);
            }

            return result;
        }

        public static byte[] DecryptDataPBKDF2(
            string data,
            string pbkdf2Password,
            string pbkdf2Salt,
            int pbkdf2Iterations)
        {
            if (pbkdf2Password.Equals("") || pbkdf2Salt.Equals("") || pbkdf2Iterations <= 0)
            {
                throw new Exception("Password and salt for the PBKDF2 algorithm can not be empty and the iteration count must be bigger than zero");
            }

            // data and salt are base 64 encoded
            byte[] decodedPrivateKeyBytes = Base64Helper.decode(data);
            byte[] decodedSalt = Base64Helper.decode(pbkdf2Salt);

            // derive bytestream from password and salt
            // via PBKDF2 - the resulting bytes (64) are
            // two AES256 keys which will be used in further steps
            PBKDF2Helper pbkdf2 = new PBKDF2Helper(pbkdf2Password, decodedSalt, pbkdf2Iterations);
            byte[] hashBytes = pbkdf2.GetBytes(64);
            int[] unsignedHashBytes = new int[64];
            for (int i = 0; i < hashBytes.Length; ++i)
            {
                unsignedHashBytes[i] = hashBytes[i] & 0xFF;
            }

            byte[] cryptoKey = new byte[32];
            BlockCopy(hashBytes, 0, cryptoKey, 0, 32);
            byte[] hmacKey = new byte[hashBytes.Length - 32];
            BlockCopy(hashBytes, 32, hmacKey, 0, 32);

            // the encrypted data holds an initialization vector
            // for the AES decryption, a HMAC-SHA-256 hash to
            // verify the given input and the actual private key bytes
            byte[] IVec = new byte[16];
            BlockCopy(decodedPrivateKeyBytes, 0, IVec, 0, 16);
            byte[] givenHmacHash = new byte[32];
            BlockCopy(decodedPrivateKeyBytes, 16, givenHmacHash, 0, 32);
            byte[] privateKeyBytes = new byte[decodedPrivateKeyBytes.Length - 48];
            BlockCopy(decodedPrivateKeyBytes, 48, privateKeyBytes, 0, decodedPrivateKeyBytes.Length - 48);

            // it is necessary to compute the HMAC-SHA-256 hash
            // again to make sure the private key, password, salt
            // and iteraton count weren't tampered with
            byte[] computedHmacHash = HashHelper.ComputeSHA256HMAC(privateKeyBytes, hmacKey);
            if (!computedHmacHash.SequenceEqual<byte>(givenHmacHash))
            {
                throw new Exception("HMAC hashes do not match, make sure you used a matching .bckey file and password");
            }

            byte[] result = DecryptData(privateKeyBytes, cryptoKey, IVec);

            Console.WriteLine("AES decryption finished");
            return result;
        }

        public static byte[] DecryptFile(
            string encryptedFilePath,
            byte[] fileCryptoKey,
            string baseIVec,
            int blockSize,
            int offset,
            int padding)
        {
            Console.WriteLine($"AES Decryption of file '{encryptedFilePath}' started");
            if (fileCryptoKey.Length <= 0 || blockSize <= 0)
            {
                throw new Exception("Crypto key for file can't be empty and block size must be bigger than zero");
            }

            // read the encrypted file
            byte[] fileBytes;
            try
            {
                fileBytes = File.ReadAllBytes(Path.GetFullPath(encryptedFilePath));
            }
            catch (IOException e)
            {
                throw new Exception("Could not read file", e);
            }

            // IVec in file header is base 64 encoded
            byte[] decodedFileIV = Base64Helper.decode(baseIVec);

            // report initial status
            int fileSize = fileBytes.Length;
            long fileSizeFivePer = Convert.ToInt64(Math.Floor(fileSize * 0.05));    // 5% of file size; for status reporting
            string byteProgress = $" (0 / {fileSize} bytes)";
            StringBuilder routeString = new StringBuilder();
            StringBuilder spaceString = new StringBuilder();
            for (int i = 0; i < 20; i++)
            {
                spaceString.Append(" ");
            }
            Console.WriteLine($"Progress: [{spaceString}]{byteProgress}");

            // decrypt each block separately with its own initialization vector
            int blockNo = 0;
            byte[] result = new byte[fileSize - offset - padding];
            for (int byteNo = offset, nextStatusThreshold = offset, currentStep = 0; byteNo <= fileSize; byteNo += blockSize, ++blockNo)
            {
                byte[] blockIVec = AESHelper.ComputeBlockIVec(decodedFileIV, blockNo, fileCryptoKey);

                // get the input data for the current block (the last block may be shorter than [blockSize] bytes)
                int end = (byteNo + blockSize >= fileSize) ? fileSize : byteNo + blockSize;
                byte[] blockInput = new byte[end - byteNo];
                BlockCopy(fileBytes, byteNo, blockInput, 0, end - byteNo);

                PaddingMode currentPadding = (end == fileSize && padding > 0) ? PaddingMode.PKCS7 : PaddingMode.None;

                // get the decrypted data for this block ...
                byte[] decryptedBlock = AESHelper.DecryptData(blockInput, fileCryptoKey, blockIVec, currentPadding);

                // ... and append it to the previous data
                BlockCopy(decryptedBlock, 0, result, byteNo - offset, decryptedBlock.Length);

                // report intermediate status every 5% 
                if (byteNo > nextStatusThreshold)
                {
                    int steps = byteNo / nextStatusThreshold;
                    nextStatusThreshold += Convert.ToInt32(fileSizeFivePer * steps);

                    currentStep += steps;
                    byteProgress = $" ({byteNo} / {fileSize} bytes)";
                    routeString.Length = 0;
                    for (int i = 0; i < currentStep; i++) 
                    { 
                        routeString.Append("#"); 
                    }
                    spaceString.Length = 0;
                    for (int i = 0; i < 20 - currentStep; i++)
                    {
                        spaceString.Append(" ");
                    }
                    Console.WriteLine($"Progress: [{routeString}{spaceString}]{byteProgress}");
                }
            }

            // newline after Status report
            byteProgress = $" ({fileSize} / {fileSize} bytes)";
            routeString.Length = 0;
            for (int i = 0; i < 20; i++)
            {
                routeString.Append("#");
            }
            Console.WriteLine($"Progress: [{routeString}]{byteProgress}");

            Console.WriteLine("AES decryption of file finished");
            return result;
        }
    }
}

