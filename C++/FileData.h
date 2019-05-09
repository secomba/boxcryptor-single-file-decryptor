#ifndef FILEINFORMATION_H
#define FILEINFORMATION_H

#include <string>
#include <vector>
#include "TypeDefs.h"

struct HeaderData
{
	unsigned int rawLen = 48;
	unsigned int coreLen;
	unsigned int corePaddingLen;
	unsigned int cipherPaddingLen;
};

class FileData
{
public:
	FileData() = default;
	FileData(const FileData&) = delete;
	FileData& operator=(const FileData&) = delete;

	bool ParseHeader(const std::string& encryptedFilePath, const std::string& outputFilePath);
	std::string GetOutputFilepath() const;
	std::string GetEncryptedFileKey() const;
	std::string GetEncryptedFilePath() const;
	std::string GetBaseIVec() const;
	unsigned int GetBlockSize() const;
	unsigned int GetHeaderLen() const;
	unsigned int GetCipherPadding() const;

private:
	std::string m_encryptedFileKey;
	std::string m_baseIVec;
	std::string m_encryptedFilePath;
	unsigned int m_blockSize;
	HeaderData m_headerData;
	std::string m_outputFilePath;

	const std::vector<byte> m_supportedFileVersion = { 98, 99, 48, 49 };

	std::string CheckOutputFilepath(const std::string& currentPath);
};

#endif