using System;
using System.Text;

namespace BCFileDecryptorCore
{
    class Base64Helper
    {
        public static byte[] encode(byte[] data)
        {
            Console.WriteLine($"Base 64 encoding of {data.Length} bytes started");

            if (data.Length <= 0)
            {
                throw new Exception("No data to encode");
            }
            byte[] result = Encoding.Default.GetBytes(Convert.ToBase64String(data));
            Console.WriteLine("Base 64 encoding finished");

            return result;
        }

        public static byte[] decode(string data)
        {
            Console.WriteLine($"Base 64 decoding of {Encoding.Default.GetBytes(data).Length} bytes started");

            if (data.Equals(""))
            {
                throw new Exception("No data to encode");
            }

            byte[] result = Convert.FromBase64String(data);
            Console.WriteLine("Base 64 decoding finished");

            return result;
        }

        public static byte[] decode(byte[] data)
        {
            Console.WriteLine($"Base 64 decoding of {data.Length} bytes started");

            if (data.Length <= 0)
            {
                throw new Exception("No data to decode");
            }

            byte[] result = Convert.FromBase64String(Encoding.Default.GetString(data));
            Console.WriteLine("Base 64 decoding finished");

            return result;
        }
    }
}
