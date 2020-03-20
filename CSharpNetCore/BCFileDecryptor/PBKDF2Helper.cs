using System;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace BCFileDecryptorCore
{
    class PBKDF2Helper
    {
        private readonly int iterations;
        private readonly byte[] salt;
        private readonly byte[] password;

        public PBKDF2Helper(string pwd, byte[] salt, int iterations)
        {
            this.iterations = iterations;
            this.salt = salt;
            password = Encoding.Default.GetBytes(pwd);
        }

        public byte[] GetBytes(int count)
        {
            Console.WriteLine($"PBKDF2 algorithm to get {count} bytes started");

            if (count < 0)
            {
                throw new Exception("Parameter 'count' can't be zero or smaller");
            }

            byte[] result;
            try
            {
                Encoding charset = Encoding.UTF8;

                // result is a 512 bits long key
                result = KeyDerivation.Pbkdf2(
                    charset.GetString(password),
                    salt,
                    KeyDerivationPrf.HMACSHA512,
                    iterations,
                    count);
            }
            catch (Exception e)
            {
                if (e is ArgumentException || e is DecoderFallbackException)
                {
                    throw new Exception("Could not derive bytes with PBKDF2", e);
                }
                throw;
            }

            Console.WriteLine("PBKDF2 algorithm finished");
            return result;
        }
    }
}
