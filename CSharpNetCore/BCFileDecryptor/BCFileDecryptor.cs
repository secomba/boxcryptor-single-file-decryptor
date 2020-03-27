using System;
using System.IO;
using static System.Buffer;

namespace BCFileDecryptorCore
{
    class BCFileDecryptor
    {
        static void Main(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("Usage: bc-file-decryptor \n"
                    + "[path to .bckey file] "
                    + "[path to encrypted file] "
                    + "[pwd] "
                    + "[path for output (optional)]");
                return;
            }

            try
            {
                Console.WriteLine("Decryption process started");

                // ============================================
                // AES decryption of private key in .bckey file
                // =============================================

                // collect information about the user account
                AccountData accountInfo = new AccountData();
                accountInfo.ParseBCKeyFile(args[0]);
                accountInfo.Password = args[2];

                // decrypt the private key from the .bckey file
                byte[] decryptedPrivateKey = AESHelper.DecryptDataPBKDF2(
                    accountInfo.EncryptedPrivateKey, accountInfo.Password,
                    accountInfo.PBKDF2Salt, accountInfo.PBKDF2Iterations
                );

                // =============================================
                // RSA decryption of file information (header)
                // =============================================

                // collect information about the file to be decrypted
                FileData fileData = new FileData();
                string outputFilePath = args.Length > 3 ? args[3] : "";
                fileData.ParseHeader(args[1], outputFilePath);

                // decrypt the file key (from the header) used for decryption of file data
                byte[] decryptedFileKey = RSAHelper.DecryptData(fileData.EncryptedFileKey, decryptedPrivateKey);

                byte[] fileCryptoKey = new byte[32];
                BlockCopy(decryptedFileKey, 32, fileCryptoKey, 0, 32);
                // =============================================
                // AES decryption of encrypted file
                // =============================================

                // decrypt the file data ...
                byte[] decryptedFileBytes = AESHelper.DecryptFile(
                    fileData.EncryptedFilePath, fileCryptoKey, fileData.BaseIVec,
                    fileData.BlockSize, fileData.HeaderLen, fileData.CipherPadding);

                File.WriteAllBytes(Path.GetFullPath(fileData.OutputFilePath), decryptedFileBytes);

                Console.WriteLine($"Successfully decrypted file '{fileData.EncryptedFilePath}', "
                    + $"output: '{fileData.OutputFilePath}'");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                if (e.StackTrace != null)
                {
                    Console.WriteLine(e.StackTrace);
                }
            }
        }
    }
}
