#ifndef RSADECRYPTOR_H
#define RSADECRYPTOR_H

#include <string>
#include <vector>
#include "TypeDefs.h"

class RSAHelper
{
public:
	RSAHelper() = delete;

	static bool DecryptData(const std::string& encryptedFileKey, const std::string& decryptedPrivateKey, std::vector<byte>& decryptedFileKey);
};

#endif