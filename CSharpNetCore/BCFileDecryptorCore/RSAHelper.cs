using System;
using System.Security.Cryptography;

namespace BCFileDecryptorCore
{
    class RSAHelper
    {
        public static byte[] decryptData(string encryptedFileKey, byte[] decryptedPrivateKey)
        {
            Console.WriteLine("RSA decryption of data has started");

            if (decryptedPrivateKey.Length <= 0)
            {
                throw new SystemException("The private key used for the RSA decryption can't be empty");
            }

            // encrypted file key is base 64 encoded
            byte[] decodedFileKey = Base64Helper.decode(encryptedFileKey);

            // private key is stored in a simplified PEM format (no header / footer) and no line breaks)
            // decode it from base 64 again to get the DER encoding needed for the key spec
            byte[] privateKeyDEREncoded = Base64Helper.decode(decryptedPrivateKey);

            // DEBUG output
            // Console.WriteLine("-DEBUG: Param: encryptedFileKey");
            // Console.WriteLine(encryptedFileKey);
            // Console.WriteLine("-DEBUG: Param: decryptedPrivateKey");
            // Console.WriteLine(ByteArrayToString(decryptedPrivateKey));
            // Console.WriteLine("-DEBUG: Decoded File Key");
            // Console.WriteLine(ByteArrayToString(decodedFileKey));
            // Console.WriteLine("-DEBUG: private Key DER encoded");
            // Console.WriteLine(ByteArrayToString(privateKeyDEREncoded));

            byte[] result;
            try
            {
                // create / load a PrivateKey from the DER encoded key
                RSA rsa = RSA.Create();
                rsa.ImportRSAPrivateKey(privateKeyDEREncoded, out int bytesRead);
                result = rsa.Decrypt(decodedFileKey, RSAEncryptionPadding.OaepSHA1);
            }
            catch (CryptographicException e)
            {
                throw new SystemException("RSA decryption unsuccessful", e);
            }

            Console.WriteLine("RSA decryption finished");
            return result;
        }

        // Helper function for debugging purposes only 
        public static string ByteArrayToString(byte[] ba)
        {
            return BitConverter.ToString(ba).Replace("-", "");
        }
    }
}