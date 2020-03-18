using System;
using System.IO;

namespace BCFileDecryptorCore
{
    class Program
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

            // Set arguments for debugging
            //args = new string[3];
            //args[0] = @"C:\shtest@gmx.de-export-2020-03-13.bckey";
            //args[1] = @"C:\Users\Hussain Sandhu\OneDrive\MyFile.txt.bc";
            //args[2] = ",,.-abcss123";

            try
            {
                Console.WriteLine("Decryption process started");

                // ============================================
                // AES decryption of private key in .bckey file
                // =============================================

                // collect information about the user account
                AccountData accountInfo = new AccountData();
                accountInfo.parseBCKeyFile(args[0]);
                accountInfo.setPassword(args[2]);

                // decrypt the private key from the .bckey file
                byte[] decryptedPrivateKey = AESHelper.decryptDataPBKDF2(
                    accountInfo.getEncryptedPrivateKey(), accountInfo.getPassword(),
                    accountInfo.getPBKDF2Salt(), accountInfo.getPBKDF2Iterations()
                );

                // =============================================
                // RSA decryption of file information (header)
                // =============================================

                // collect information about the file to be decrypted
                FileData fileData = new FileData();
                string outputFilePath = args.Length > 3 ? args[3] : "";
                fileData.parseHeader(args[1], outputFilePath);

                // decrypt the file key (from the header) used for decryption of file data
                byte[] decryptedFileKey = RSAHelper.decryptData(fileData.getEncryptedFileKey(), decryptedPrivateKey);
                // DEBUG
                //Console.WriteLine("-DEBUG: Result from RSAHelper.decryptData(...):");
                //Console.WriteLine(ByteArrayToString(decryptedFileKey));

                byte[] fileCryptoKey = new byte[32];
                System.Buffer.BlockCopy(decryptedFileKey, 32, fileCryptoKey, 0, 32);
                // =============================================
                // AES decryption of encrypted file
                // =============================================

                // decrypt the file data ...
                byte[] decryptedFileBytes = AESHelper.decryptFile(
                    fileData.getEncryptedFilePath(), fileCryptoKey, fileData.getBaseIVec(),
                    fileData.getBlockSize(), fileData.getHeaderLen(), fileData.getCipherPadding());

                File.WriteAllBytes(Path.GetFullPath(fileData.getOutputFilePath()), decryptedFileBytes);

                Console.WriteLine("Successfully decrypted file '" + fileData.getEncryptedFilePath() + "', "
                    + "output: '" + fileData.getOutputFilePath() + "'");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                if (e.StackTrace != null)
                    Console.WriteLine(e.StackTrace);
            }
        }

        // Helper function for debugging purposes only
        public static string ByteArrayToString(byte[] ba)
        {
            return BitConverter.ToString(ba).Replace("-", "");
        }

        // Helper function for debugging purposes only
        public static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
    }
}
