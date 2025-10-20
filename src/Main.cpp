#include <array>
#include <cstdint>
#include <exception>
#include <ios>
#include <iostream>
#include <print>
#include <string>
#include <vector>

#include "RS2Tools.hpp"

namespace
{

#ifndef NDEBUG

// Just checks whether a debugger is attached or not
// in order to do certain things differently with a debugger for
// ease of debugging.
bool DebuggerPresent()
{
#if WINDOWS
    return IsDebuggerPresent();
#else
    // TODO: Linux version?
    return false;
#endif // WINDOWS
}

#else

constexpr bool DebuggerPresent()
{
    return false;
}

#endif // NDEBUG

// Helper macro to make debugging easier when a debugger is attached.
#define THROW_IF_DEBUGGING()    \
if (DebuggerPresent())         \
{                               \
    throw;                      \
}

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

template<std::size_t T>
void PrintBuffer(const std::array<std::uint32_t, T>& buffer)
{
    std::print("{{");
    for (auto i = 0; i < T; ++i)
    {
        std::print("{}", buffer[i]);
        if (i < T - 1)
        {
            std::print(", ");
        }
    }
    std::println("}}");
}

template<std::size_t T>
void DecryptData(
    std::string_view name,
    const std::array<std::uint32_t, T>& data)
{
    std::string decrypted((T + 1) * sizeof(std::uint32_t), '\0');
    std::println("{}:", name);
    RS2::Crypto::DecryptString(data.data(), data.size(), decrypted.data());
    std::println("decrypted: {}\n", decrypted);
}

void DecryptData(
    std::string_view name,
    const std::vector<std::uint32_t>& data)
{
    std::string decrypted((data.size() + 1) * sizeof(std::uint32_t), '\0');
    std::println("{}:", name);
    RS2::Crypto::DecryptString(data.data(), data.size(), decrypted.data());
    std::println("decrypted: {}\n", decrypted);
}

// ReSharper disable once CppConstValueFunctionReturnType
WIN_MAYBE_CONSTEXPR std::size_t StupidSize(std::string_view str)
{
    return std::floor((str.size() + 1) / sizeof(std::uint32_t));
}

void RunRS2Checks()
{
    std::vector<std::uint32_t> encrypted;
    std::string decrypted(RS2::Crypto::GXXTEABufferSize * sizeof(std::uint32_t), '\0');

    // TKLMutator.u
    constexpr auto tklMutatorMd5 = "f2b3d8a799a9300634ff067ac612745d";
    constexpr std::array tklMutatorData0 = {
        2000924894U, 277274360U, 4140362311U, 0U, 0U, 0U, 0U, 0U,
    };
    constexpr std::array tklMutatorData0Alt = {
        2000924894U, 277274360U, 4140362311U,
    };
    constexpr std::array tklMutatorData1 = {
        2504114439U, 3344273490U, 953332573U, 3691125115U, 1687282814U, 1065781761U, 902691679U, 934229910U,
    };

    constexpr std::string_view s1 = "TKLMutator.u";
    WIN_MAYBE_CONSTEXPR std::size_t s1Size = StupidSize(s1);
    encrypted.resize(s1Size);
    std::println("s1Size: {}", s1Size);
    RS2::Crypto::EncryptString(s1.data(), encrypted.data());
    std::println("encrypted buffer:");
    PrintBuffer(encrypted);
    DecryptData(s1, encrypted);

    constexpr std::string_view twi = "www.tripwireinteractive.com";
    WIN_MAYBE_CONSTEXPR std::size_t twiSize = StupidSize(twi);
    std::println("twiSize: {}", s1Size);
    encrypted.resize(twiSize);
    RS2::Crypto::EncryptString(twi.data(), encrypted.data());
    std::println("encrypted buffer:");
    PrintBuffer(encrypted);
    DecryptData("www.tripwireinteractive.com", encrypted);

    constexpr std::array addr0 = {667268793U, 572063549U, 2821723169U, 1079833058U, 57665466U, 315357024U, 3557871184U};
    DecryptData("addr0", addr0);

    constexpr std::array addr1 = {
        515829103U, 73578521U, 2980778981U, 1850491108U, 2735934040U,
        460470580U, 3106607331U, 1148387282U, 3310707735U, 3965381053U
    };
    DecryptData("addr1", addr1);

    DecryptData("tklMutatorData0", tklMutatorData0);
    DecryptData("tklMutatorData0Alt", tklMutatorData0Alt);
    DecryptData("tklMutatorData1", tklMutatorData1);
}

} // namespace

int main()
{
    try
    {
        RunRS2Checks();
        std::cout << std::flush;
        return EXIT_SUCCESS;
    }
    catch (const std::exception& ex)
    {
        std::println("main error: {}", ex.what());
        THROW_IF_DEBUGGING();
        return EXIT_FAILURE;
    }
    // Catch anything else that was unhandled.
    catch (...)
    {
        THROW_IF_DEBUGGING();
        return EXIT_FAILURE;
    }
}
