#ifndef BASE64HELPER_H
#define BASE64HELPER_H

#include <string>
#include <vector>
#include "TypeDefs.h"

class Base64Helper
{
public:
	Base64Helper() = delete;

	static bool Encode(const std::vector<byte>& data, std::string& output);
	static bool Decode(const std::string& data, std::vector<byte>& output);
};

#endif