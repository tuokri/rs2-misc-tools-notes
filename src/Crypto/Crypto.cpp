#include <cstdint>
#include <limits>
#include <memory>

#include "Crypto/Crypto.hpp"

constexpr std::uint32_t PRIVATE_KEY_KEY0 = 0xea2e0f;
constexpr std::uint32_t PRIVATE_KEY_KEY1 = 0x953;
constexpr std::uint32_t PRIVATE_KEY_KEY2 = 0xde19d3a7;
constexpr std::uint32_t PRIVATE_KEY_KEY3 = 0x8281d;
constexpr auto INVERSE_DELTA = -0x61c88647;

#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))

namespace RS2::Crypto
{
// NOTE: Len should be at least 2? XXTEA.
void Decrypt(std::uint32_t* value, std::uint32_t length, std::uint32_t* key)
{
    std::uint32_t delta = INVERSE_DELTA, y, z, sum;
    std::uint32_t p, rounds, e, i;

    delta = std::numeric_limits<std::uint32_t>::max() - delta;
    rounds = 6 + 52 / length;
    sum = rounds * delta;
    y = value[0];

    for (i = 0; i < rounds; i++)
    {
        e = (sum >> 2) & 3;

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

char* DecryptString(std::uint32_t* encrypted, std::uint32_t length, char* string)
{
    int stringlength;
    std::uint32_t key[4], tempvalues[128], i;

    key[0] = PRIVATE_KEY_KEY0;
    key[1] = PRIVATE_KEY_KEY1;
    key[2] = PRIVATE_KEY_KEY2;
    key[3] = PRIVATE_KEY_KEY3;

    memcpy(tempvalues, encrypted, length * sizeof(std::uint32_t));

    Decrypt(tempvalues, length, key);

    for (i = 0, stringlength = 0; i < length; i++)
    {
        string[stringlength++] = tempvalues[i] & 255;
        string[stringlength++] = (tempvalues[i] & 65280) >> 8;

        if (string[stringlength - 1] == 0)
            break;

        string[stringlength++] = (tempvalues[i] & 16711680) >> 16;

        if (string[stringlength - 1] == 0)
            break;

        string[stringlength++] = (tempvalues[i] & 4278190080) >> 24;
    }

    if (string[stringlength - 1] != 0)
        string[stringlength] = 0;

    return string;
}

void Encrypt(std::uint32_t* value, std::uint32_t length, std::uint32_t* key)
{
    std::uint32_t delta = INVERSE_DELTA, y, z, sum;
    std::uint32_t p, rounds, e;

    rounds = 6 + 52 / length;
    sum = 0;
    z = value[length - 1];
    delta = std::numeric_limits<std::uint32_t>::max() - delta;

    do
    {
        sum += delta;
        e = (sum >> 2) & 3;

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
    int stringlength, i;
    std::uint32_t length, key[4];

    stringlength = strlen(string);

    for (i = 0, length = 0; i < stringlength; i += 4, length++)
    {
        encrypted[length] = string[i];

        if (i + 1 < stringlength)
        {
            encrypted[length] += string[i + 1] << 8;

            if (i + 2 < stringlength)
            {
                encrypted[length] += string[i + 2] << 16;

                if (i + 3 < stringlength)
                {
                    encrypted[length] += string[i + 3] << 24;
                }
            }
        }
    }

    key[0] = PRIVATE_KEY_KEY0;
    key[1] = PRIVATE_KEY_KEY1;
    key[2] = PRIVATE_KEY_KEY2;
    key[3] = PRIVATE_KEY_KEY3;

    Encrypt(encrypted, length, key);
}

} // namespace RS2::Crypto
