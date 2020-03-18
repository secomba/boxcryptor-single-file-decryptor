#include <iostream>
#include <stdexcept>
#include "HashHelper.h"
#include "sha.h"
#include "hmac.h"
#include "filters.h"

bool HashHelper::ComputeSHA256HMAC(const std::vector<byte>& data, const std::vector<byte>& key, std::vector<byte>& hmac, bool silent)
{
	if (!silent)
	{
		std::cout << "Computation of HMAC-SHA-256 hash with " << data.size() << " bytes started" << std::endl;
	}

	// check if there is data to hash
	if (data.size() > 0 && key.size() > 0)
	{
		hmac.clear();
		hmac.resize(CryptoPP::SHA256::DIGESTSIZE);

		try
		{
			// construct HMAC object used to create hash and ...
			const byte *plainKey = key.data();
			CryptoPP::HMAC<CryptoPP::SHA256> hmacForFilter(plainKey, key.size());

			// ... use it to transform the input
			const byte *in = data.data();
			byte *out = hmac.data();
			CryptoPP::ArraySource(in, data.size(), true, new CryptoPP::HashFilter(hmacForFilter, new CryptoPP::ArraySink(out, CryptoPP::SHA256::DIGESTSIZE)));
		}
		catch (const std::exception&)
		{
			std::cerr << "Computation of HMAC-SHA-256 failed" << std::endl;
			throw;
		}

		if (!silent)
		{
			std::cout << "HMAC-SHA-256 computation finished" << std::endl;
		}
		return true;
	}
	else
	{
		throw std::runtime_error("No data from which to calculate hmac");
	}
}

bool HashHelper::ComputeSHA512HMAC(const std::vector<byte>& data, const std::vector<byte>& key, std::vector<byte>& hmac, bool silent)
{
	if (!silent)
	{
		std::cout << "Computation of HMAC-SHA-512 hash with " << data.size() << " bytes started" << std::endl;
	}

	// check if there is data to hash 
	if (data.size() > 0 && key.size() > 0)
	{
		hmac.clear();
		hmac.resize(CryptoPP::SHA512::DIGESTSIZE);

		try
		{
			// construct HMAC object used to create hash and ...
			const byte *plainKey = key.data();
			CryptoPP::HMAC<CryptoPP::SHA512> hmacForFilter(plainKey, key.size());

			// ... use it to transform the input
			const byte *in = data.data();
			byte *out = hmac.data();
			CryptoPP::ArraySource(in, data.size(), true, new CryptoPP::HashFilter(hmacForFilter, new CryptoPP::ArraySink(out, CryptoPP::SHA512::DIGESTSIZE)));
		}
		catch (const std::exception&)
		{
			std::cerr << "Computation of HMAC-SHA-512 failed" << std::endl;
			throw;
		}

		if (!silent)
		{
			std::cout << "HMAC-SHA-512 computation finished" << std::endl;
		}
		return true;
	}
	else
	{
		throw std::runtime_error("No data from which to calculate hmac");;
	}
}