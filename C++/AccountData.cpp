#include "AccountData.h"
#include <fstream>
#include <iostream>
#include <vector>
#include <stdexcept>
#include "TypeDefs.h"

// this method should ideally be implemented using a proper JSON library,
// but for the purpose of demonstrating which infos are needed from
// the file header simple string searches should be sufficient
bool AccountData::ParseBCKeyFile(const std::string& keyfilePath)
{
	std::cout << "Parsing .bckey file: '" << keyfilePath << "'" << std::endl;

	if (keyfilePath.substr(keyfilePath.length() - 6) != ".bckey")
	{
		throw std::runtime_error("Given filepath does not have the right extension ('.bckey'), please specify a Boxcryptor key file");
	}

	std::ifstream keyFile(keyfilePath, std::ios::binary | std::ios::ate);
	if (!keyFile.good())
	{
		std::string errorMsg(".bckey-File (" + keyfilePath + ") can't be opened (make sure the provided path is correct, the file exists and you have the right to open the file)");
		throw std::runtime_error(errorMsg.c_str());
	}

	this->m_bckeyFilepath = keyfilePath;

	// get the file size ...
	std::streamoff pos = keyFile.tellg();
	keyFile.seekg(0, std::ios::beg);

	// ... and read the complete file
	std::string keyFileData;
	keyFileData.resize(static_cast<size_t>(pos));
	keyFile.read(&keyFileData[0], pos);

	// find the (first) user object
	std::string searchString = R"("users")";
	size_t posUserBegin = keyFileData.find(searchString);
	posUserBegin = keyFileData.find("{", posUserBegin + searchString.length());
	size_t posUserEnd = keyFileData.find("}", posUserBegin + 1);

	// and the 'privateKey' within
	searchString = R"("privateKey")";
	size_t posBegin = keyFileData.find(searchString, posUserBegin + 1);
	posBegin = keyFileData.find(R"(")", posBegin + searchString.length());

	// check if we are still in the right block / JSON object
	if (posBegin > posUserEnd)
	{
		throw std::runtime_error("The (first) user object has no suitable 'privateKey' value");
	}
	size_t posEnd = keyFileData.find(R"(")", posBegin + 1);

	if (posBegin != std::string::npos && posEnd != std::string::npos && posEnd - posBegin > 0)
	{
		this->m_encryptedPrivateKey = keyFileData.substr(posBegin + 1, posEnd - posBegin - 1);
	}
	else
	{
		throw std::runtime_error("Could not find encrypted private key in keyfile");
	}

	// and the 'salt' within
	searchString = R"("salt")";
	posBegin = keyFileData.find(searchString, posUserBegin + 1);
	posBegin = keyFileData.find(R"(")", posBegin + searchString.length());

	// check if we are still in the right block / JSON object
	if (posBegin > posUserEnd)
	{
		throw std::runtime_error("The (first) user object has no suitable 'salt' value");
	}
	posEnd = keyFileData.find(R"(")", posBegin + 1);

	if (posBegin != std::string::npos && posEnd != std::string::npos && posEnd - posBegin > 0)
	{
		this->m_pbkdf2Salt = keyFileData.substr(posBegin + 1, posEnd - posBegin - 1);
	}
	else
	{
		throw std::runtime_error("Could not find salt in keyfile");
	}

	// and the 'kdfIterations' within
	searchString = R"("kdfIterations")";
	posBegin = keyFileData.find(searchString, posUserBegin + 1);
	posBegin = keyFileData.find(":", posBegin + searchString.length());

	// check if we are still in the right block / JSON object
	if (posBegin > posUserEnd)
	{
		throw std::runtime_error("The (first) user object has no suitable 'kdfIterations' value");
	}
	posEnd = keyFileData.find(",", posBegin + 1);

	if (posBegin != std::string::npos && posEnd != std::string::npos && posEnd - posBegin > 0)
	{
		std::string iterations = keyFileData.substr(posBegin + 1, posEnd - posBegin - 1);
		try { this->m_pbkdf2Iterations = std::stoi(iterations); }
		catch (...) { throw std::runtime_error("Could not convert iterations value to integer"); }
	}
	else
	{
		throw std::runtime_error("Could not find iteration count in keyfile");
	}

	std::cout << "Parsing finished" << std::endl;

	return true;
}


void AccountData::SetPassword(const std::string& pw)
{
	if (pw.length() > 0)
	{
		this->m_password = pw;
	}
	else
	{
		throw std::runtime_error("Password can't be empty");
	}
}

std::string AccountData::GetPassword() const
{
	return this->m_password;
}

std::string AccountData::GetPBKDF2Salt() const
{
	return this->m_pbkdf2Salt;
}

unsigned int AccountData::GetPBKDF2Iterations() const
{
	return this->m_pbkdf2Iterations;
}

std::string AccountData::GetEncryptedPrivateKey() const
{
	return this->m_encryptedPrivateKey;
}