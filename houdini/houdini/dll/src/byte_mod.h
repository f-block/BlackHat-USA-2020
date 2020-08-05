#ifndef _HOUDINI_BYTE_MOD_H
#define _HOUDINI_BYTE_MOD_H

#include <sstream>
#include <iomanip>

std::string hexStr(const char* data, int len);
int char2int(char input);
void hex2bin(const char* src, char* target);
void endecrypt_inplace(char *input, int len, char *key);
void encrypt(char *input, char* output, int len, char *key);
void get_encrypted_hexstring(char* dst, int dst_len, char* src, char* key);

#endif