#include <iostream>
#include <stdexcept>
#include "Base64Helper.h"
#include "base64.h"

bool Base64Helper::Encode(const std::vector<byte>& data, std::string& output)
{
	std::cout << "Base 64 encoding of " << data.size() << " bytes started" << std::endl;

	// check if there is data to encode
	if (data.size() > 0)
	{
		output = "";

		// get a pointer to the beginning of the arbitrary data and ...
		const byte *d = data.data();

		try
		{
			// ... use it as source for the Crypto++ base 64 encoder
			CryptoPP::ArraySource(d, data.size(), true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(output), false));
		}
		catch (const std::exception&)
		{
			std::cerr << "Encoding data to base 64 failed" << std::endl;
			throw;
		}

		std::cout << "Base 64 encoding finished" << std::endl;
		return true;
	}
	else
	{
		throw std::runtime_error("No data to encode");
	}
}

bool Base64Helper::Decode(const std::string& data, std::vector<byte>& output)
{
	std::cout << "Base 64 decoding of " << data.size() << " bytes started" << std::endl;

	// check if there is data to encode
	if (data.size() > 0)
	{
		try
		{
			// decode input data with the Crypto++ base 64 decoder
			std::string out;
			CryptoPP::StringSource(data, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(out)));
			output = std::vector<byte>(out.begin(), out.end());
		}
		catch (const std::exception&)
		{
			std::cerr << "Decoding data from base 64 failed" << std::endl;
			throw;
		}

		std::cout << "Base 64 decoding finished" << std::endl;
		return true;
	}
	else
	{
		throw std::runtime_error("No data to decode");
	}
}