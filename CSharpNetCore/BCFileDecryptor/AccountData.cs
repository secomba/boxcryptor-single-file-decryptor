using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Text.Json;

namespace BCFileDecryptorCore
{

    class AccountData
    {
        private string password;
        public string Password
        {
            get { return password; }
            set
            {
                if (value == "")
                    throw new ArgumentException("Password can't be empty");
                password = value;
            }
        }
        public string EncryptedPrivateKey { get; private set; }
        public string PBKDF2Salt { get; private set; }
        public int PBKDF2Iterations { get; private set; }

        // this method should ideally be implemented using a proper JSON library,
        // but for the purpose of demonstrating which infos are needed from
        // the file header the built in scripting solution should be sufficient
        public void ParseBCKeyFile(string keyFilePath)
        {
            Console.WriteLine($"Parsing .bckey file: '{keyFilePath}'");

            if (!keyFilePath.EndsWith(".bckey"))
            {
                throw new Exception("Given filepath does not have the right extension ('.bckey'), please specify a Boxcryptor key file");
            }

            try
            {
                byte[] keyFileDate = File.ReadAllBytes(Path.GetFullPath(keyFilePath));

                // parse the json data in .bckey-file
                string keyFileContents = File.ReadAllText(keyFilePath, UTF8Encoding.UTF8);
                JsonDocument doc = JsonDocument.Parse(keyFileContents);
                JsonElement root = doc.RootElement;
                JsonElement userInfo = root.GetProperty("users");
                JsonElement.ArrayEnumerator userInfoArray = userInfo.EnumerateArray();
                List<JsonElement> userInfoList = userInfoArray.ToList<JsonElement>();
                this.EncryptedPrivateKey = userInfoList[0].GetProperty("privateKey").GetString();
                this.PBKDF2Salt = userInfoList[0].GetProperty("salt").GetString();
                this.PBKDF2Iterations = userInfoList[0].GetProperty("kdfIterations").GetInt32();
            }
            catch (Exception e)
            {
                if (e is IOException)
                    throw new Exception("BCKey file ({keyFilePath}) could not be parsed", e);
                else
                    throw new Exception("BCKey file ({keyFilePath}) could not be opened (make sure the provided path "
                                      + "is correct, the file exists and you have the right to open the file)", e);
            }

            Console.WriteLine("Parsing finished");
        }

    }
}
