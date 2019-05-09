# BC File Decryptor

### USE WITH CAUTION
**This project is intended as a documentation on how to decrypt files encrypted with Boxcryptor (2.x). Only use it with copies of your files and never use it in a production environment.
When using this software you agree that Secomba GmbH will not accept any responsibility for any potential loss of data.**

### Description
The purpose of this repository is to show / document how to decrypt Boxcryptor files (.bc) with your individual keyfile (.bckey) and your password as input. If you want to know more about the decryption process or include similiar functionality in your own applications you can have a look at the source code in your preferred language.
For information about the build process please consult the corresponding readme files in the language subfolders.
**Please also note that you should only give sensitive information like the password to your Boxcryptor account (especially in combination with your personal .bckey-file) to applications you trust, we therefore recommend you having a look at the source code to be absolutely sure how the password is used before doing so.**

### Usage
After having successfully build the application you can run it with the following command line arguments:
1. The path to your personal .bckey-file (you can get this file by following this guide: https://support.boxcryptor.com/display/DOCEN/08.+Key+export)
2. The path to the encrypted file you want to decrypt
3. The password to your Boxcryptor account
4. Optionally: The path where the decrypted file should be saved to (if not specified, the output will be derived from the encrypted file and will be located in the same folder)

If your input was correct, you should now have the decrypted file at the path you specified.
