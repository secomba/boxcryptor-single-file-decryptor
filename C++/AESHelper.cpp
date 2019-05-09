#include "AESHelper.h"
#include <vector>
#include <iostream>
#include <iterator>
#include <iomanip>
#include <stdexcept>
#include "Base64Helper.h"
#include "PBKDF2Helper.h"
#include "HashHelper.h"
#include "aes.h"
#include "modes.h"
#include "files.h"

bool AESHelper::DecryptDataPBKDF2(const std::string& data, const std::string& pbkdf2Password, const std::string& pbkdf2Salt, unsigned int pbkdf2Iterations, std::string& decryptedData)
{
	std::cout << "AES decryption of data started" << std::endl;

	if (pbkdf2Password.length() > 0 && pbkdf2Salt.length() > 0 && pbkdf2Iterations > 0)
	{
		// data and salt are base 64 encoded
		std::vector<byte> decodedPrivateKeyBytes;
		Base64Helper::Decode(data, decodedPrivateKeyBytes);

		std::vector<byte> decodedSalt;
		Base64Helper::Decode(pbkdf2Salt, decodedSalt);

		// derive bytestream from password and salt
		// via PBKDF2 - the resulting bytes (64) are 
		// two AES-256 keys which will be used in further steps
		PBKDF2Helper pbkdf2(pbkdf2Password, decodedSalt, pbkdf2Iterations);
		std::vector<byte> hashBytes;
		pbkdf2.GetBytes(64, hashBytes);
		auto cryptoKey = std::vector<byte>(hashBytes.begin(), hashBytes.begin() + 32);
		auto hmacKey = std::vector<byte>(hashBytes.begin() + 32, hashBytes.end());

		// the encrypted data holds an initialization vector
		// for the AES decryption, a HMAC-SHA-256 hash to
		// verify the given input and the actual private key bytes
		auto IVec = std::vector<byte>(decodedPrivateKeyBytes.begin(), decodedPrivateKeyBytes.begin() + 16);
		auto givenHmacHash = std::vector<byte>(decodedPrivateKeyBytes.begin() + 16, decodedPrivateKeyBytes.begin() + 48);
		auto privateKeyBytes = std::vector<byte>(decodedPrivateKeyBytes.begin() + 48, decodedPrivateKeyBytes.end());

		// it is necessary to compute the HMAC-SHA-256 hash
		// again to make sure the private key, password, salt
		// and iteration count weren't tampered with
		std::vector<byte> computedHmacHash;
		HashHelper::ComputeSHA256HMAC(privateKeyBytes, hmacKey, computedHmacHash);
		if (givenHmacHash != computedHmacHash)
		{
			throw std::runtime_error("HMAC hashes do not match, make sure you used a matching .bckey file and password");
		}

		AESHelper::DecryptData(privateKeyBytes, cryptoKey, IVec, decryptedData);

		std::cout << "AES decryption finished" << std::endl;
		return true;
	}
	else
	{
		throw std::runtime_error("Password and salt for the PBKDF2 algorithm can not be empty and the iteration count must be bigger than zero");
	}
}

bool AESHelper::DecryptFile(
	const std::string& encryptedFilePath, const std::vector<byte>& fileCryptoKey,
	const std::string& baseIVec, unsigned int blockSize, unsigned int offset,
	unsigned int padding, std::vector<byte>& decryptedFileBytes)
{
	std::cout << "AES decryption of file '" << encryptedFilePath << "' started" << std::endl;

	if (fileCryptoKey.size() > 0 && blockSize > 0)
	{
		// open the encrypted file, ...
		std::ifstream ifs(encryptedFilePath, std::ios::binary | std::ios::ate);
		if (!ifs.good())
		{
			std::string errorMsg("Encrypted file (" + encryptedFilePath + ") can't be opened (make sure the provided path is correct, the file exists and you have the right to open the file)");
			throw std::runtime_error(errorMsg.c_str());
		}

		// ... get the size ...
		std::streamoff pos = ifs.tellg();
		ifs.seekg(0, std::ios::beg);

		// ... and copy it into a byte vector to work with the data
		std::vector<char> fileBytes(static_cast<size_t>(pos));
		ifs.read(&fileBytes[0], pos);

		// IVec in file header is base 64 encoded
		std::vector<byte> decodedFileIV;
		Base64Helper::Decode(baseIVec, decodedFileIV);

		// create result vector and reserve enough space
		// to fit the complete decrypted file
		decryptedFileBytes.clear();
		decryptedFileBytes.reserve(fileBytes.size());
		unsigned long blockNo = 0;

		// report initial status
		size_t fileSize = fileBytes.size();
		std::string fileSizeStr = std::to_string(fileSize);
		auto fileSizeFivePer = static_cast<size_t>(std::floor(fileSize * 0.05));
		std::string byteProgress = " (0 / " + fileSizeStr + " bytes)";
		std::cout << "Progress: [" << std::setfill(' ') << std::setw(21) << "]" << std::left << std::setw(79) << byteProgress << std::right;

		// decrypt each block seperately with its own initialization vector
		for (size_t byteNo = offset, nextStatusThreshold = offset, currentStep = 0; byteNo < fileSize; byteNo += blockSize, ++blockNo)
		{
			auto blockIVec = AESHelper::ComputeBlockIVec(decodedFileIV, blockNo, fileCryptoKey);

			// get the input data for the current block (the last block may be shorter than [blockSize] bytes)
			auto iterEnd = (byteNo + blockSize >= fileSize) ? fileBytes.end() : fileBytes.begin() + byteNo + blockSize;
			std::vector<byte> blockInput(fileBytes.begin() + byteNo, iterEnd);

			// use PKCS7 padding for the last block if a cipher padding size greater than 0 was specified in file header
			auto currentPadding = (iterEnd == fileBytes.end() && padding > 0) ? CryptoPP::StreamTransformationFilter::PKCS_PADDING : CryptoPP::StreamTransformationFilter::NO_PADDING;

			// get the decrypted data for this block ...
			std::string decryptedBlockBytes;
			AESHelper::DecryptData(blockInput, fileCryptoKey, blockIVec, decryptedBlockBytes, currentPadding);

			// ... and append it to the data of previous blocks
			decryptedFileBytes.insert(decryptedFileBytes.end(), decryptedBlockBytes.begin(), decryptedBlockBytes.end());

			// report intermediate status every 5%
			if (byteNo > nextStatusThreshold)
			{
				int steps = byteNo / nextStatusThreshold;
				nextStatusThreshold += fileSizeFivePer * steps;

				currentStep += steps;
				byteProgress = " (" + std::to_string(byteNo) + " / " + fileSizeStr + " bytes)";
				std::cout << std::setfill('\b') << std::setw(100) << "" << std::setfill('#') << std::setw(currentStep) << "" << std::setfill(' ') << std::setw(21 - currentStep)
					<< "]" << std::left << std::setw(79) << byteProgress << std::right;
			}
		}

		// newline and buffer flush after status report
		byteProgress = " (" + fileSizeStr + " / " + fileSizeStr + " bytes)";
		std::cout << std::setfill('\b') << std::setw(100) << "" << std::setfill('#') << std::setw(21) << "]" << std::setfill(' ')
			<< std::left << std::setw(79) << byteProgress << std::right << std::endl;
		
		std::cout << "AES decryption of file finished" << std::endl;
		return true;
	}
	else
	{
		throw std::runtime_error("Crypto key for file can't be empty and block size must be bigger than zero");
	}
}

// from https://github.com/vgough/encfs/blob/559c30d01ed0a3d19258b12f15eae8785accc60f/encfs/SSL_Cipher.cpp#L626
/*private*/ std::vector<byte> AESHelper::ComputeBlockIVec(std::vector<byte> IVec, unsigned long seed, std::vector<byte> key)
{
	if (IVec.size() > 0 && key.size() > 0)
	{
		std::vector<byte> md(8);
		for (int i = 0; i < 8; ++i)
		{
			md.at(i) = static_cast<byte>(seed & 0xff);
			seed >>= 8;
		}

		std::vector<byte> data(IVec.size() + md.size());
		for (size_t i = 0; i < IVec.size(); ++i)
		{
			data.at(i) = IVec.at(i);
		}

		for (size_t i = 0; i < md.size(); ++i)
		{
			data.at(i + IVec.size()) = md.at(i);
		}

		std::vector<byte> buffer;
		HashHelper::ComputeSHA256HMAC(data, key, buffer, true);

		std::vector<byte> result(IVec.size());
		for (size_t i = 0; i < IVec.size(); ++i)
		{
			result.at(i) = buffer.at(i);
		}

		return result;
	}
	else
	{
		throw std::runtime_error("Base initialization vector and crypto key can't be empty");
	}
}

/*private*/ bool AESHelper::DecryptData(
	const std::vector<byte>& data, const std::vector<byte>& cryptoKey,
	const std::vector<byte>& IVec, std::string& output,
	CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme paddingMode /* = CryptoPP::StreamTransformationFilter::PKCS_PADDING*/)
{
	if (data.size() > 0 && cryptoKey.size() > 0 && IVec.size() > 0)
	{
		CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption aesDecryptor;

		// provide the Crypto++ decryptor with the necessary
		// key and initialization vector needed for decryption
		const byte *key = cryptoKey.data();
		const byte *iv = IVec.data();
		aesDecryptor.SetKeyWithIV(key, cryptoKey.size(), iv, IVec.size());

		// Crypto++ takes the data (input) from the 'ArraySource' and transforms
		// it via the aesDecryptor into the decrypted output, which is then dumped
		// into the 'StringSink' (decryptedData)
		// PKCS7 padding (https://en.wikipedia.org/wiki/PKCS) is used in case the 
		// last data block is smaller than the block size used by AES (16 bytes)
		const byte *input = data.data();
		CryptoPP::ArraySource(
			input, data.size(), true,
			new CryptoPP::StreamTransformationFilter(
				aesDecryptor, new CryptoPP::StringSink(output), paddingMode));

		return true;
	}
	else
	{
		throw std::runtime_error("Encrypted data, crypto key and initialization vector can't be empty");
	}
}