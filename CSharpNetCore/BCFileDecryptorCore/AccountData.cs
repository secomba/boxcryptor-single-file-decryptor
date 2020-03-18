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
        private string bcKeyFilePath; // not used in Java program
        private string password;
        private string encryptedPrivateKey;
        private string pbkdf2Salt;
        private int pbkdf2Iterations;

        // this method should ideally be implemented using a proper JSON library,
        // but for the purpose of demonstrating which infos are needed from
        // the file header the built in scripting solution should be sufficient
        public void parseBCKeyFile(string keyFilePath)
        {
            Console.WriteLine("Parsing .bckey file: '" + keyFilePath + "'");

            if (!keyFilePath.Substring(keyFilePath.Length - 6).Equals(".bckey"))
            {
                throw new SystemException("Given filepath does not have the right extension ('.bckey'), please specify a Boxcryptor key file");
            }

            // Check if file is a regular file
            // Note: Possibly more FileAttributes other than 'Normal' and 'Archive' should be allowed
            FileAttributes attributes = File.GetAttributes(keyFilePath); 
            if (attributes != FileAttributes.Normal && attributes != FileAttributes.Archive)
            {
                throw new SystemException("Encrypted file (" + keyFilePath + ") can't be opened (make sure the provided path "
                        + "is correct, the file exists and you have the right to open the file)");
            }

            this.bcKeyFilePath = keyFilePath;

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
                this.encryptedPrivateKey = userInfoList[0].GetProperty("privateKey").GetString();
                this.pbkdf2Salt = userInfoList[0].GetProperty("salt").GetString();
                this.pbkdf2Iterations = userInfoList[0].GetProperty("kdfIterations").GetInt32();
            }
            catch (IOException e)
            {
                throw new SystemException("BCKey file could not be parsed", e);
            }

            Console.WriteLine("Parsing finished");
        }

        public void setPassword(string pw)
        {
            if (pw.Equals(""))
            {
                throw new ArgumentException("Password can't be empty");
            }

            this.password = pw;
        }

        public string getPassword()
        {
            return this.password;
        }

        public string getEncryptedPrivateKey()
        {
            return this.encryptedPrivateKey;
        }

        public string getPBKDF2Salt()
        {
            return this.pbkdf2Salt;
        }

        public int getPBKDF2Iterations()
        {
            return this.pbkdf2Iterations;
        }
    }
}
