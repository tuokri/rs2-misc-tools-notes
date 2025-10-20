#include <cstdint>
#include <cstring>
#include <limits>

#include "Crypto/Crypto.hpp"

constexpr std::uint32_t GPrivateKey0 = 0xea2e0f;
constexpr std::uint32_t GPrivateKey1 = 0x953;
constexpr std::uint32_t GPrivateKey2 = 0xde19d3a7;
constexpr std::uint32_t GPrivateKey3 = 0x8281d;
// constexpr auto GInverseDelta = -0x61c88647;
constexpr auto GDelta = 0x9e3779b9;

#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))

namespace RS2::Crypto
{

// NOTE: Len should be at least 2? XXTEA.
void Decrypt(std::uint32_t* value, std::uint32_t length, const std::uint32_t* key)
{
    // std::uint32_t delta = GInverseDelta;
    std::uint32_t z;
    std::uint32_t p;

    // delta = std::numeric_limits<std::uint32_t>::max() - delta;
    constexpr auto delta = GDelta;
    const std::uint32_t rounds = 6 + 52 / length;
    std::uint32_t sum = rounds * delta;
    std::uint32_t y = value[0];

    for (std::uint32_t i = 0; i < rounds; i++)
    {
        const std::uint32_t e = sum >> 2 & 3;

        for (p = length - 1; p > 0; p--)
        {
            z = value[p - 1];
            y = value[p] -= MX;
        }

        z = value[length - 1];
        y = value[0] -= MX;

        sum -= delta;
    }
}

char* DecryptString(const std::uint32_t* encrypted, std::uint32_t length, char* string)
{
    int stringLen;
    std::uint32_t key[4];
    std::uint32_t buffer[GXXTEABufferSize * 4];
    std::uint32_t i;

    key[0] = GPrivateKey0;
    key[1] = GPrivateKey1;
    key[2] = GPrivateKey2;
    key[3] = GPrivateKey3;

    std::memcpy(buffer, encrypted, length * sizeof(std::uint32_t));
    Decrypt(buffer, length, key);

    for (i = 0, stringLen = 0; i < length; i++)
    {
        string[stringLen++] = buffer[i] & 255;
        string[stringLen++] = (buffer[i] & 65280) >> 8;

        if (string[stringLen - 1] == 0)
            break;

        string[stringLen++] = (buffer[i] & 16711680) >> 16;

        if (string[stringLen - 1] == 0)
            break;

        string[stringLen++] = (buffer[i] & 4278190080) >> 24;
    }

    if (string[stringLen - 1] != 0)
        string[stringLen] = 0;

    return string;
}

void Encrypt(std::uint32_t* value, std::uint32_t length, const std::uint32_t* key)
{
    // std::uint32_t delta = GInverseDelta;
    std::uint32_t y;
    std::uint32_t p;

    std::uint32_t rounds = 6 + 52 / length;
    std::uint32_t sum = 0;
    std::uint32_t z = value[length - 1];
    // delta = std::numeric_limits<std::uint32_t>::max() - delta;
    constexpr auto delta = GDelta;

    do
    {
        sum += delta;
        const std::uint32_t e = sum >> 2 & 3;

        for (p = 0; p < length - 1; p++)
        {
            y = value[p + 1];
            z = value[p] += MX;
        }

        y = value[0];
        z = value[length - 1] += MX;
    } while (--rounds);
}

// NOTE: length must be at least 5? XXXTEA.
void EncryptString(const char* string, std::uint32_t* encrypted)
{
    int i;
    std::uint32_t length;
    std::uint32_t key[4];

    const std::size_t stringLen = std::strlen(string);

    for (i = 0, length = 0; i < stringLen; i += 4, length++)
    {
        encrypted[length] = static_cast<unsigned char>(string[i]);

        if (i + 1 < stringLen)
        {
            encrypted[length] += string[i + 1] << 8;

            if (i + 2 < stringLen)
            {
                encrypted[length] += string[i + 2] << 16;

                if (i + 3 < stringLen)
                {
                    encrypted[length] += string[i + 3] << 24;
                }
            }
        }
    }

    key[0] = GPrivateKey0;
    key[1] = GPrivateKey1;
    key[2] = GPrivateKey2;
    key[3] = GPrivateKey3;

    Encrypt(encrypted, length, key);
}

} // namespace RS2::Crypto
