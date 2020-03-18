using System;
using System.Security.Cryptography;

namespace BCFileDecryptorCore
{
    class HashHelper
    {
        public static byte[] ComputeSHA256HMAC(byte[] data, byte[] key)
        {
            return ComputeSHA256HMAC(data, key, false);
        }

        public static byte[] ComputeSHA256HMAC(byte[] data, byte[] key, bool silent)
        {
            if (!silent)
            {
                Console.WriteLine("Computation of HMAC-SHA-256 hash with " + data.Length + " bytes started");
            }

            if (data.Length <= 0 || key.Length <= 0)
            {
                throw new SystemException("No data from which to calculate hmac");
            }

            byte[] finalData;
            try
            {
                HMACSHA256 hmac = new HMACSHA256(key);
                finalData = hmac.ComputeHash(data);

            }
            catch (Exception e)
            {
                throw new SystemException("Computation of HMAC-SHA-256 failed", e);
            }

            return finalData;
        }
    }
}

