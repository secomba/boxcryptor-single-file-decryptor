using System;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace BCFileDecryptorCore
{
    class PBKDF2Helper
    {
        private int iterations;
        private byte[] salt;
        private byte[] password;

        public PBKDF2Helper(string pwd, byte[] salt, int iterations)
        {
            this.iterations = iterations;
            this.salt = salt;
            this.password = Encoding.Default.GetBytes(pwd);
        }

        public byte[] getBytes(int count)
        {
            Console.WriteLine("PBKDF2 algorithm to get " + count + " bytes started");

            if (count < 0)
            {
                throw new SystemException("Parameter 'count' can't be zero or smaller");
            }

            byte[] result = new byte[0];
            try
            {
                Encoding charset = Encoding.UTF8;

                // result is a 512 bits long key
                result = KeyDerivation.Pbkdf2(
                    charset.GetString(this.password),
                    this.salt,
                    KeyDerivationPrf.HMACSHA512,
                    this.iterations,
                    count);
            }
            catch (Exception e)
            {
                if (e is ArgumentException || e is DecoderFallbackException)
                {
                    throw new SystemException("Could not derive bytes with PBKDF2", e);
                }
            }

            Console.WriteLine("PBKDF2 algorithm finished");
            return result;
        }
    }
}
