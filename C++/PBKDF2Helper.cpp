#include <iostream>
#include <stdexcept>
#include "PBKDF2Helper.h"
#include "algparam.h"
#include "pwdbased.h"
#include "sha.h"

PBKDF2Helper::PBKDF2Helper(std::string pwd, std::vector<byte> salt, int iterations = 5000)
	: m_iterations(iterations)
	, m_salt(salt)
{
	this->m_password = std::vector<byte>(pwd.begin(), pwd.end());
}

bool PBKDF2Helper::GetBytes(unsigned int count, std::vector<byte>& derivedBytes)
{
	std::cout << "PBKDF2 algorithm to get " << count << " bytes started" << std::endl;

	if (count > 0)
	{
		derivedBytes.clear();
		derivedBytes.resize(count);

		CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA512> pbkdf2;

		byte *derived = derivedBytes.data();
		const byte *pwd = this->m_password.data();
		const byte *salt = this->m_salt.data();

		try
		{
			pbkdf2.DeriveKey(derived, count, 0, pwd, this->m_password.size(), salt, this->m_salt.size(), this->m_iterations);
		}
		catch (const std::exception&)
		{
			std::cerr << "Could not derive bytes with PBKDF2" << std::endl;
			throw;
		}

		std::cout << "PBKDF2 algorithm finished" << std::endl;
		return true;
	}
	else
	{
		throw std::runtime_error("Parameter 'count' can't be zero");
	}
}