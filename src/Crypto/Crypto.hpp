#pragma once

#include <cstddef>
#include <string_view>

namespace RS2::Crypto
{

constexpr std::size_t GXXTEABufferSize = 128;

void Decrypt(std::uint32_t* value, std::uint32_t length, const std::uint32_t* key);

char* DecryptString(const std::uint32_t* encrypted, std::uint32_t length, char* string);

void Encrypt(std::uint32_t* value, std::uint32_t length, const std::uint32_t* key);

void EncryptString(const char* string, std::uint32_t* encrypted);

// Return the required number of uint_32s for a given string.
constexpr std::size_t BufferSizeU32(std::string_view str)
{
    return (str.size() + sizeof(std::uint32_t) - 1) / sizeof(std::uint32_t);
}

} // namespace RS2::Crypto
