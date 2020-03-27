using System;
using System.Security.Cryptography;

namespace BCFileDecryptorCore
{
    class RSAHelper
    {
        public static byte[] DecryptData(string encryptedFileKey, byte[] decryptedPrivateKey)
        {
            Console.WriteLine("RSA decryption of data has started");

            if (decryptedPrivateKey.Length <= 0)
            {
                throw new Exception("The private key used for the RSA decryption can't be empty");
            }

            // encrypted file key is base 64 encoded
            byte[] decodedFileKey = Base64Helper.decode(encryptedFileKey);

            // private key is stored in a simplified PEM format (no header / footer) and no line breaks)
            // decode it from base 64 again to get the DER encoding needed for the key spec
            byte[] privateKeyDEREncoded = Base64Helper.decode(decryptedPrivateKey);

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
                throw new Exception("RSA decryption unsuccessful", e);
            }

            Console.WriteLine("RSA decryption finished");
            return result;
        }
    }
}