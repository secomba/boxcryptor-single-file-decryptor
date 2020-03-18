#ifndef SECRFC2898DERIVEBYTES_H
#define SECRFC2898DERIVEBYTES_H

#include <string>
#include <vector>
#include "TypeDefs.h"

class PBKDF2Helper
{
public:
	PBKDF2Helper(std::string pwd, std::vector<byte> salt, int iterations);
	bool GetBytes(unsigned int count, std::vector<byte>& derivedBytes);

private:
	int m_iterations;
	std::vector<byte> m_salt;
	std::vector<byte> m_password;
};

#endif