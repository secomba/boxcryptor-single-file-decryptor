#ifndef AESDECRYPTOR_H
#define AESDECRYPTOR_H

#include <string>
#include <vector>
#include "TypeDefs.h"
#include "filters.h"

class AESHelper
{
public:
	AESHelper() = delete;

	static bool DecryptDataPBKDF2(
		const std::string& data, const std::string& pbkdf2Password,
		const std::string& pbkdf2Salt, unsigned int pbkdf2Iterations, std::string& decryptedData);
	static bool DecryptFile(
		const std::string& encryptedFilePath, const std::vector<byte>& fileCryptoKey,
		const std::string& baseIVec, unsigned int blockSize, unsigned int offset,
		unsigned int padding, std::vector<byte>& decryptedFileBytes);

private:
	static std::vector<byte> ComputeBlockIVec(std::vector<byte> ivec, unsigned long seed, std::vector<byte> key);
	static bool DecryptData(
		const std::vector<byte>& data, const std::vector<byte>& cryptoKey, const std::vector<byte>& IVec, std::string& output,
		bool isUserGeneratedData, 
		CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme paddingMode = CryptoPP::StreamTransformationFilter::PKCS_PADDING);
};

#endif