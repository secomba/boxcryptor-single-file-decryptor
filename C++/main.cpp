#include <fstream>
#include <iostream>	
#include <string>
#include "Base64Helper.h"
#include "PBKDF2Helper.h"
#include "HashHelper.h"
#include "AccountData.h"
#include "FileData.h"
#include "AESHelper.h"
#include "RSAHelper.h"

int main(int argc, char *argv[])
{
	if (argc < 4)
	{
		std::cout << "Usage: bc-file-decryptor.exe "
			<< "[path to .bckey file] "
			<< "[path to encrypted file] "
			<< "[pwd] "
			<< "[path for output (optional)] "
			<< std::endl;
		return 0;
	}

	// for the sake of keeping this program short just catch
	// all exceptions in one place and show the error before exiting
	try
	{
		std::cout << "Decryption process started" << std::endl;

		// ============================================
		// AES decryption of private key in .bckey file
		// =============================================

		// collect information about the user account
		AccountData accountInfo;
		accountInfo.ParseBCKeyFile(std::string(argv[1]));
		accountInfo.SetPassword(std::string(argv[3]));

		// decrypt the private key from the .bckey file
		std::string decryptedPrivateKey;
		AESHelper::DecryptDataPBKDF2(accountInfo.GetEncryptedPrivateKey(), accountInfo.GetPassword(), accountInfo.GetPBKDF2Salt(), accountInfo.GetPBKDF2Iterations(), decryptedPrivateKey);


		// =============================================
		// RSA decryption of file information (header)
		// =============================================

		// collect information about the file to be decrypted
		FileData fileData;
		auto outputFilepath = argc > 4 ? std::string(argv[4]) : "";
		fileData.ParseHeader(std::string(argv[2]), outputFilepath);

		// decrypt the file key (from file header) used for decryption of file data
		std::vector<byte> decryptedFileKey;
		RSAHelper::DecryptData(fileData.GetEncryptedFileKey(), decryptedPrivateKey, decryptedFileKey);
		
		auto fileCryptoKey = std::vector<byte>(decryptedFileKey.begin() + 32, decryptedFileKey.begin() + 64);

		// =============================================
		// AES decryption of encrypted file
		// =============================================

		// decrypt the file data ...
		std::vector<byte> decryptedFileBytes;
		AESHelper::DecryptFile(fileData.GetEncryptedFilePath(), fileCryptoKey, fileData.GetBaseIVec(), fileData.GetBlockSize(), fileData.GetHeaderLen(), fileData.GetCipherPadding(), decryptedFileBytes);

		std::ofstream ofs(fileData.GetOutputFilepath(), std::ios::binary);
		if (!ofs.good())
		{
			std::string errorMsg("Can't create encrypted file at location '" + fileData.GetOutputFilepath() + "' (make sure you have the necessary file system rights to write to this location or specify another path)");
			throw std::runtime_error(errorMsg.c_str());
		}
		
		// ... and write it to disk
		ofs.write((char *)decryptedFileBytes.data(), decryptedFileBytes.size());

		std::cout << "Successfully decrypted file '" << fileData.GetEncryptedFilePath() << "', output: '" << fileData.GetOutputFilepath() << "'" << std::endl;
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
	}
	
	return 0;
}