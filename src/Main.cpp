#include <array>
#include <cstdint>
#include <exception>
#include <print>
#include <string>
#include <string_view>

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

template<std::size_t T>
void PrintBuffer(const std::array<std::uint32_t, T>& buffer)
{
    const auto str = std::string{
        reinterpret_cast<const char*>(buffer.data()),
        buffer.size() * sizeof(std::uint32_t)
    };
    // Only up to the first '\0'.
    const auto s = std::string_view{str};
    std::println("{}", s);
}

void RunRS2Checks()
{
    constexpr std::uint32_t bufferSize = 512;
    std::array<std::uint32_t, bufferSize> encrypted{};

    // TKLMutator.u
    constexpr auto tklMutatorMD5 = "f2b3d8a799a9300634ff067ac612745d";
    constexpr std::array tklMutatorData0 = {
        2000924894U, 277274360U, 4140362311U, 0U, 0U, 0U, 0U, 0U
    };
    constexpr std::array tklMutatorData1 = {
        2504114439U, 3344273490U, 953332573U, 3691125115U, 1687282814U, 1065781761U, 902691679U, 934229910U
    };
    constexpr auto s1 = "TKLMutator.u";
    std::string decrypted(bufferSize, '\0');
    RS2::Crypto::EncryptString(s1, encrypted.data());
    RS2::Crypto::DecryptString(encrypted.data(), encrypted.size(), decrypted.data());
    PrintBuffer(encrypted);
    std::println("decrypted: {}", decrypted);
}

} // namespace

int main()
{
    try
    {
        RunRS2Checks();
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
