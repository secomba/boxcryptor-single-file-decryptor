#ifndef UTILS_H
#define UTILS_H

#include <vector>
#include "TypeDefs.h"

class HashHelper
{
public:
	HashHelper() = delete;

	static bool ComputeSHA256HMAC(const std::vector<byte>& data, const std::vector<byte>& key, std::vector<byte>& hmac, bool silent = false);
	static bool ComputeSHA512HMAC(const std::vector<byte>& data, const std::vector<byte>& key, std::vector<byte>& hmac, bool silent = false);
};

#endif
