#include "byte_mod.h"

std::string hexStr(const char* data, int len)
{
	std::stringstream ss;
	ss << std::hex;
	for (int i(0); i<len; ++i)
		ss << std::setw(2) << std::setfill('0') << (int)data[i];
	return ss.str();
}

// https://stackoverflow.com/questions/17261798/converting-a-hex-string-to-a-byte-array
int char2int(char input)
{
	if (input >= '0' && input <= '9')
		return input - '0';
	if (input >= 'A' && input <= 'F')
		return input - 'A' + 10;
	if (input >= 'a' && input <= 'f')
		return input - 'a' + 10;
	throw std::invalid_argument("Invalid input string");
}

// This function assumes src to be a zero terminated sanitized string with
// an even number of [0-9a-f] characters, and target to be sufficiently large
void hex2bin(const char* src, char* target)
{
	while (*src && src[1])
	{
		*(target++) = char2int(*src) * 16 + char2int(src[1]);
		src += 2;
	}
}


// in place decryption
void endecrypt_inplace(char *input, int len, char *key)
{
	int key_length = strlen(key);
	for (int i = 0; i < len; i++){
		if (input[i] != '\0' && input[i] != key[i % key_length])
			input[i] = input[i] ^ key[i % key_length];
	}

}

void encrypt(char *input, char* output, int len, char *key){
	int key_length = strlen(key);

	for (int i = 0; i < len; i++){
		if (input[i] != '\0' && input[i] != key[i % key_length])
			output[i] = input[i] ^ key[i % key_length];
		else
			output[i] = input[i];
	}
}

void get_encrypted_hexstring(char* dst, int dst_len, char* src, char* key){
	int src_len = strlen(src);
	endecrypt_inplace(src, src_len, key);
	strncpy_s(dst, dst_len, hexStr(src, src_len).c_str(), src_len * 2);
}