#include <array>
#include <cassert>
#include <exception>
#include <filesystem>
#include <print>
#include <string>
#include <vector>

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "RS2Tools.hpp"
#include "Crypto/Crypto.hpp"

void PrintBuffer(const std::vector<std::uint32_t>& buffer)
{
    std::print("{{");
    for (auto i = 0; i < buffer.size(); ++i)
    {
        std::print("{}", buffer[i]);
        if (i < buffer.size() - 1)
        {
            std::print(", ");
        }
    }
    std::println("}}");
}

// TODO: maybe strip trailing NULs in DecryptString funcs?

template<std::size_t T>
std::string DecryptData(
    std::string_view name,
    const std::array<std::uint32_t, T>& data)
{
    std::string decrypted(T * sizeof(std::uint32_t), '\0');
    std::println("{}:", name);
    RS2::Crypto::DecryptString(data.data(), data.size(), decrypted.data());
    std::println("decrypted: {}\n", decrypted);
    return decrypted;
}

std::string DecryptData(
    std::string_view name,
    const std::vector<std::uint32_t>& data)
{
    std::string decrypted(data.size() * sizeof(std::uint32_t), '\0');
    std::println("{}:", name);
    RS2::Crypto::DecryptString(data.data(), data.size(), decrypted.data());
    std::println("decrypted: {}\n", decrypted);
    return decrypted;
}

void CheckString(std::string_view str)
{
    std::println("CheckString: '{}'", str);
    std::vector<std::uint32_t> encrypted;
    const std::size_t strSize = RS2::Crypto::BufferSizeU32(str);
    std::println("str.size()           : {}", str.size());
    std::println("strSize (U32s)       : {}", strSize);
    encrypted.resize(strSize);
    RS2::Crypto::EncryptString(str.data(), encrypted.data());
    std::println("encrypted buffer:");
    PrintBuffer(encrypted);
    const auto decrypted = DecryptData(str, encrypted);
    std::fflush(stdout);
    CHECK(std::strcmp(str.data(), decrypted.data()) == 0);
}

TEST_CASE("test basic crypto")
{
    std::vector<std::uint32_t> encrypted;
    std::string decrypted;

    // TKLMutator.u
    constexpr auto tklMutatorMd5 = "f2b3d8a799a9300634ff067ac612745d";
    constexpr std::array tklMutatorData0 = {
        2000924894U, 277274360U, 4140362311U, 0U, 0U, 0U, 0U, 0U,
    };
    constexpr std::array tklMutatorData0Alt = {
        2000924894U, 277274360U, 4140362311U,
    };
    constexpr std::array tklMutatorData1 = {
        2504114439U, 3344273490U, 953332573U, 3691125115U,
        1687282814U, 1065781761U, 902691679U, 934229910U,
    };

    constexpr std::string_view s1 = "TKLMutator.u";
    constexpr std::size_t s1Size = RS2::Crypto::BufferSizeU32(s1);
    encrypted.resize(s1Size);
    std::println("s1Size: {}", s1Size);
    RS2::Crypto::EncryptString(s1.data(), encrypted.data());
    std::println("encrypted buffer:");
    PrintBuffer(encrypted);
    decrypted = DecryptData(s1, encrypted);
    CHECK(std::strcmp(decrypted.data(), s1.data()) == 0);

    constexpr std::size_t tklMutatorMd5Size = RS2::Crypto::BufferSizeU32(tklMutatorMd5);
    encrypted.resize(tklMutatorMd5Size);
    RS2::Crypto::EncryptString(tklMutatorMd5, encrypted.data());
    decrypted = DecryptData("tklMutatorMd5", encrypted);
    CHECK(std::strcmp(decrypted.data(), tklMutatorMd5) == 0);

    constexpr std::string_view twi = "www.tripwireinteractive.com";
    constexpr std::size_t twiSize = RS2::Crypto::BufferSizeU32(twi);
    std::println("twiSize: {}", twiSize);
    encrypted.resize(twiSize);
    RS2::Crypto::EncryptString(twi.data(), encrypted.data());
    std::println("encrypted buffer:");
    PrintBuffer(encrypted);
    decrypted = DecryptData(twi, encrypted);
    CHECK(std::strcmp(decrypted.data(), twi.data()) == 0);

    constexpr std::array addr0 = {
        667268793U, 572063549U, 2821723169U, 1079833058U,
        57665466U, 315357024U, 3557871184U,
    };
    DecryptData("addr0", addr0);

    constexpr std::array addr1 = {
        515829103U, 73578521U, 2980778981U, 1850491108U, 2735934040U,
        460470580U, 3106607331U, 1148387282U, 3310707735U, 3965381053U
    };
    DecryptData("addr1", addr1);

    DecryptData("tklMutatorData0", tklMutatorData0);
    DecryptData("tklMutatorData0Alt", tklMutatorData0Alt);
    DecryptData("tklMutatorData1", tklMutatorData1);

    // GOM3.U / ced0ebe54a5f0771059251601fc92069
    constexpr std::array gom3name = {1040990352U, 2495382815U};
    constexpr std::array gom3md5 = {
        3029409044U, 1812751812U, 2284506666U, 3317781048U,
        309846119U, 4155870121U, 239163896U, 3563961329U,
    };
    decrypted = DecryptData("gom3name", gom3name);
    CHECK(std::strcmp(decrypted.data(), "GOM3.U") == 0);
    decrypted = DecryptData("gom3md5", gom3md5);
    CHECK(std::strcmp(decrypted.data(), "ced0ebe54a5f0771059251601fc92069") == 0);

    constexpr auto strings = std::to_array<std::string_view>({
        "GOM3.U",
        "     x",
        "      5",
        "      55",
        "     ####",
        "      6asd",
        "TKLMutator.U",
        "AAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBCCCCCCCCCCCCDDDDDDDDDDXXXX",
        "AAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBCCCCCCCCCCCXDDDDDDDDDDDXXXX",
        "AAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBCCCCCCCCCCCCDDDDDDDDDDDDXXXX",
        "AAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBCCCCCCCCCCCCDDDDDDDDDDDDDXXXX",
        "AAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBCCCCCCCCCCCCDDDDDDDDDDDDDDDXXX",
        "AAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBCCCCCCCCCCCCDDDDDDDDDDDDDDDDDXX",
        "AAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBCCCCCCCCCCCCDDDDDDDDDDDDDDDDDXXX",
        "AAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBCCCCCCCCCCCCDDDDDDDDDDDDDDDDDXXXX1",
        "AAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBCCCCCCCCCCCCDDDDDDDDDDDDDDDDDXXXX23",
        "AAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBCCCCCCCCCCCCDDDDDDDDDDDDDDDDDXXXX444",
    });
    for (const auto& s: strings)
    {
        CheckString(s);
    }
}
