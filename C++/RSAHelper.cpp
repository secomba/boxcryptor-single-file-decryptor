#include "RSAHelper.h"
#include <iostream>
#include <stdexcept>
#include "Base64Helper.h"
#include "rsa.h"
#include "osrng.h"

bool RSAHelper::DecryptData(const std::string& encryptedFileKey, const std::string& decryptedPrivateKey, std::vector<byte>& decryptedFileKey)
{
	std::cout << "RSA decryption of data started" << std::endl;

	if (decryptedPrivateKey.size() > 0)
	{
		// encrypted file key is base 64 encoded
		std::vector<byte> decodedFileKey;
		Base64Helper::Decode(encryptedFileKey, decodedFileKey);

		// private key is stored in a simplified PEM format (no header/footer and no line breaks)
		// decode it from base 64 again to get the DER encoding needed by Crypto++
		std::vector<byte> privateKeyDEREncoded;
		Base64Helper::Decode(decryptedPrivateKey, privateKeyDEREncoded);

		// dump the DER encoded private key into a (source) format Crypto++ can use
		const byte *pk = privateKeyDEREncoded.data();
		CryptoPP::ArraySource pkSource(pk, privateKeyDEREncoded.size(), true);

		// create / load a RSA private key from the DER encoded key 
		// and make sure it is valid
		CryptoPP::RSA::PrivateKey privateRSAKey;
		privateRSAKey.BERDecodePrivateKey(pkSource, false, 0);
		CryptoPP::AutoSeededRandomPool rng;
		if (!privateRSAKey.Validate(rng, 3))
		{
			throw std::runtime_error("Private RSA key could not be validated");
		}

		// initialize the RSA decryptor with the created private key 
		CryptoPP::RSAES_OAEP_SHA_Decryptor rsaDecryptor(privateRSAKey);

		// make sure the output vector is big enough to hold all of the plain text
		decryptedFileKey.clear();
		decryptedFileKey.resize(rsaDecryptor.MaxPlaintextLength(decodedFileKey.size()));

		// decrypt the input und save it in the output vector
		const byte *encryptedKey = decodedFileKey.data();
		byte *decryptedKey = decryptedFileKey.data();
		auto result = rsaDecryptor.Decrypt(rng, encryptedKey, decodedFileKey.size(), decryptedKey);

		// and finally, resize the output vector from the
		// max decrypted length to the actual decrypted length
		decryptedFileKey.resize(result.messageLength);

		std::cout << "RSA decryption finished" << std::endl;
		return true;
	}
	else
	{
		throw std::runtime_error("The private key used for the RSA decryption can't be of length 0");
	}
}