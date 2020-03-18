#include "FileData.h"
#include <fstream>
#include <iostream>
#include <vector>
#include <stdexcept>
#include "TypeDefs.h"

// this method should ideally be implemented using a proper JSON library,
// but for the purpose of demonstrating which infos are needed from
// the file header simple string searches should be sufficient
bool FileData::ParseHeader(const std::string& encryptedFilePath, const std::string& outputFilePath)
{
	std::cout << "Parsing header of encrypted file: '" << encryptedFilePath << "'" << std::endl;

	if (encryptedFilePath.substr(encryptedFilePath.length() - 3) != ".bc")
	{
		throw std::runtime_error("Given filepath does not have the right extension ('.bc'), please specify a Boxcryptor encrypted file");
	}

	std::ifstream headerFile(encryptedFilePath, std::ios::binary);
	if (!headerFile.good())
	{
		std::string errorMsg("Encrypted file (" + encryptedFilePath + ") can't be opened (make sure the provided path is correct, the file exists and you have the right to open the file)");
		throw std::runtime_error(errorMsg.c_str());
	}

	this->m_encryptedFilePath = encryptedFilePath;

	// read the first 16 bytes which contain the file version
	// and information about the length of the different file parts
	std::vector<char> rawHeaderBytes(16);
	headerFile.read(&rawHeaderBytes[0], 16);

	auto fileVersionBytes = std::vector<byte>(rawHeaderBytes.begin(), rawHeaderBytes.begin() + 4);
	if (fileVersionBytes != this->m_supportedFileVersion)
	{
		throw std::runtime_error("Unknown file version found in header, aborting...");
	}

	auto headerCoreLenBytes = std::vector<byte>(rawHeaderBytes.begin() + 4, rawHeaderBytes.begin() + 8);
	auto headerPaddingLenBytes = std::vector<byte>(rawHeaderBytes.begin() + 8, rawHeaderBytes.begin() + 12);
	auto cipherPaddingLenBytes = std::vector<byte>(rawHeaderBytes.begin() + 12, rawHeaderBytes.begin() + 16);

	unsigned int headerRawLen = 48; // always 48 bytes
	unsigned int headerCoreLen = headerCoreLenBytes.at(3) << 24 | headerCoreLenBytes.at(2) << 16 | headerCoreLenBytes.at(1) << 8 | headerCoreLenBytes.at(0);
	unsigned int headerPaddingLen = headerPaddingLenBytes.at(3) << 24 | headerPaddingLenBytes.at(2) << 16 | headerPaddingLenBytes.at(1) << 8 | headerPaddingLenBytes.at(0);
	unsigned int cipherPaddingLen = cipherPaddingLenBytes.at(3) << 24 | cipherPaddingLenBytes.at(2) << 16 | cipherPaddingLenBytes.at(1) << 8 | cipherPaddingLenBytes.at(0);

	this->m_headerData.rawLen = headerRawLen;
	this->m_headerData.coreLen = headerCoreLen;
	this->m_headerData.corePaddingLen = headerPaddingLen;
	this->m_headerData.cipherPaddingLen = cipherPaddingLen;

	// go to the end of the raw header and read the core header
	headerFile.seekg(this->m_headerData.rawLen);
	std::vector<char> coreHeaderBytes(headerCoreLen);
	headerFile.read(&coreHeaderBytes[0], this->m_headerData.coreLen);

	std::string coreHeader(coreHeaderBytes.begin(), coreHeaderBytes.end());
	
	// find the blocksize
	std::string searchString = R"("blockSize")";
	size_t posBegin = coreHeader.find(searchString);
	posBegin = coreHeader.find(":", posBegin + searchString.length());
	size_t posEnd = coreHeader.find(",", posBegin + 1);

	if (posBegin != std::string::npos && posEnd != std::string::npos && posEnd - posBegin > 0)
	{
		std::string blockSize = coreHeader.substr(posBegin + 1, posEnd - posBegin - 1);
		try { this->m_blockSize = std::stoi(blockSize); }
		catch (...) { throw std::runtime_error("Could not convert block size to integer"); }
	}
	else
	{
		throw std::runtime_error("Could not find block size in file header");
	}

	// find the initialization vector
	searchString = R"("iv")";
	posBegin = coreHeader.find(searchString);
	posBegin = coreHeader.find(R"(")", posBegin + searchString.length());
	posEnd = coreHeader.find(R"(")", posBegin + 1);

	if (posBegin != std::string::npos && posEnd != std::string::npos && posEnd - posBegin > 0)
	{
		this->m_baseIVec = coreHeader.substr(posBegin + 1, posEnd - posBegin - 1);
	}
	else
	{
		throw std::runtime_error("Could not find initialization vector in file header");
	}

	// find the (first) encrypted file key object
	searchString = R"("encryptedFileKeys")";
	posBegin = coreHeader.find(searchString);
	posBegin = coreHeader.find("{", posBegin + searchString.length());
	posEnd = coreHeader.find("}", posBegin + 1);

	// and the 'value' within
	searchString = R"("value")";
	posBegin = coreHeader.find(searchString, posBegin + 1);
	posBegin = coreHeader.find(R"(")", posBegin + searchString.length());

	// check if we are still in the right block / JSON object
	if (posBegin > posEnd)
	{
		throw std::runtime_error("The (first) file key object has no suitable key value");
	}
	posEnd = coreHeader.find(R"(")", posBegin + 1);

	if (posBegin != std::string::npos && posEnd != std::string::npos && posEnd - posBegin > 0)
	{
		this->m_encryptedFileKey = coreHeader.substr(posBegin + 1, posEnd - posBegin - 1);
	}
	else
	{
		throw std::runtime_error("Could not find file key in file header");
	}

	this->m_outputFilePath = this->CheckOutputFilepath(outputFilePath);

	std::cout << "Parsing finished" << std::endl;
	return true;
}

std::string FileData::GetOutputFilepath() const
{
	return this->m_outputFilePath;
}

std::string FileData::GetEncryptedFileKey() const
{
	return this->m_encryptedFileKey;
}

std::string FileData::GetEncryptedFilePath() const
{
	return this->m_encryptedFilePath;
}

std::string FileData::GetBaseIVec() const
{
	return this->m_baseIVec;
}

unsigned int FileData::GetBlockSize() const
{
	return this->m_blockSize;
}

unsigned int FileData::GetHeaderLen() const
{
	return this->m_headerData.rawLen + this->m_headerData.coreLen + this->m_headerData.corePaddingLen;
}

unsigned int FileData::GetCipherPadding() const
{
	return this->m_headerData.cipherPaddingLen;
}

// appends a incrementing number to either the output path
// or the original path if no output was given until
// a path is found for which no file exists yet
// CAUTION: this can break if file names are too long
/*private*/ std::string FileData::CheckOutputFilepath(const std::string& currentPath)
{
	int postFix = 1;
	std::string newPath = currentPath;
	std::string originalPath = currentPath;
	bool suitablePathFound = false;
	while (!suitablePathFound)
	{
		if (newPath.length() == 0)
		{
			std::cout << "Output filepath is empty, deriving it from input" << std::endl;

			// first, get rid of the .bc extension
			size_t startPos = 0;
			size_t endPos = this->m_encryptedFilePath.find_last_of(".");
			if (endPos == std::string::npos) { break; }

			newPath = originalPath = this->m_encryptedFilePath.substr(startPos, endPos);
		}

		if (std::ifstream(newPath))
		{
			std::cout << "Output filepath '" << newPath << "' already exists, deriving a new one" << std::endl;

			// insert a number after the file name
			size_t extensionPos = originalPath.find_last_of(".");
			if (extensionPos == std::string::npos) { break; }

			newPath = originalPath.substr(0, extensionPos) + " (" + std::to_string(postFix) + ")" + originalPath.substr(extensionPos);
			++postFix;
		}
		else
		{
			suitablePathFound = true;
			break;
		}

		std::cout << "New output filepath: " << newPath << std::endl;
	}

	if (!suitablePathFound)
	{
		throw std::runtime_error("Could not find a usable output filepath");
	}

	return newPath;
}