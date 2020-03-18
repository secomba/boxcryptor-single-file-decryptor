#ifndef ACCOUNTINFORMATION_H
#define ACCOUNTINFORMATION_H

#include <string>

class AccountData
{
public:
	AccountData() = default;

	AccountData(const AccountData&) = delete;
	AccountData& operator=(const AccountData&) = delete;

	bool ParseBCKeyFile(const std::string& keyfilePath);
	void SetPassword(const std::string& pw);
	std::string GetPassword() const;
	std::string GetPBKDF2Salt() const;
	unsigned int GetPBKDF2Iterations() const;
	std::string GetEncryptedPrivateKey() const;

private:
	std::string m_bckeyFilepath;
	std::string m_password;
	std::string m_encryptedPrivateKey;
	std::string m_pbkdf2Salt;
	unsigned int m_pbkdf2Iterations;
};

#endif