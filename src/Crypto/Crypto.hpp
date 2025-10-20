#pragma once

namespace RS2::Crypto
{

void Decrypt(std::uint32_t* value, std::uint32_t length, const std::uint32_t* key);

char* DecryptString(const std::uint32_t* encrypted, std::uint32_t length, char* string);

void Encrypt(std::uint32_t* value, std::uint32_t length, const std::uint32_t* key);

void EncryptString(const char* string, std::uint32_t* encrypted);

} // namespace RS2::Crypto
