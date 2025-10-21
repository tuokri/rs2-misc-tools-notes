#include <array>
#include <cassert>
#include <exception>
#include <filesystem>
#include <iostream>
#include <print>
#include <string>
#include <vector>

#include <boost/program_options.hpp>

#include "RS2Tools.hpp"

namespace
{

namespace po = boost::program_options;
namespace fs = std::filesystem;

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
if (DebuggerPresent())          \
{                               \
    throw;                      \
}

constexpr std::size_t BufferSizeU32(std::string_view str)
{
    return (str.size() + sizeof(std::uint32_t) - 1) / sizeof(std::uint32_t);
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
    const std::size_t strSize = BufferSizeU32(str);
    std::println("str.size()           : {}", str.size());
    std::println("strSize (U32s)       : {}", strSize);
    encrypted.resize(strSize);
    RS2::Crypto::EncryptString(str.data(), encrypted.data());
    std::println("encrypted buffer:");
    PrintBuffer(encrypted);
    const auto decrypted = DecryptData(str, encrypted);
    std::fflush(stdout);
    assert(std::strcmp(str.data(), decrypted.data()) == 0);
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
        2504114439U, 3344273490U, 953332573U, 3691125115U,
        1687282814U, 1065781761U, 902691679U, 934229910U,
    };

    constexpr std::string_view s1 = "TKLMutator.u";
    constexpr std::size_t s1Size = BufferSizeU32(s1);
    encrypted.resize(s1Size);
    std::println("s1Size: {}", s1Size);
    RS2::Crypto::EncryptString(s1.data(), encrypted.data());
    std::println("encrypted buffer:");
    PrintBuffer(encrypted);
    DecryptData(s1, encrypted);

    constexpr std::size_t tklMutatorMd5Size = BufferSizeU32(tklMutatorMd5);
    encrypted.resize(tklMutatorMd5Size);
    RS2::Crypto::EncryptString(tklMutatorMd5, encrypted.data());
    DecryptData("tklMutatorMd5", encrypted);

    constexpr std::string_view twi = "www.tripwireinteractive.com";
    constexpr std::size_t twiSize = BufferSizeU32(twi);
    std::println("twiSize: {}", twiSize);
    encrypted.resize(twiSize);
    RS2::Crypto::EncryptString(twi.data(), encrypted.data());
    std::println("encrypted buffer:");
    PrintBuffer(encrypted);
    DecryptData(twi, encrypted);

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

    // GOM3.u / ced0ebe54a5f0771059251601fc92069
    constexpr std::array gom3name = {1040990352U, 2495382815U};
    constexpr std::array gom3md5 = {
        3029409044U, 1812751812U, 2284506666U, 3317781048U,
        309846119U, 4155870121U, 239163896U, 3563961329U,
    };
    DecryptData("gom3name", gom3name);
    DecryptData("gom3md5", gom3md5);

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

} // namespace

int main(int argc, char** argv)
{
    try
    {
        po::options_description desc("Options");
        const auto defaultOutDir = fs::current_path().parent_path();
        desc.add_options()("help,h", "print the help message");

        po::positional_options_description p;
        p.add("input-file", -1);

        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);

        const auto& prog = fs::path(argv[0]).filename().string();

        if (vm.contains("help"))
        {
            std::println("Usage: {} [input-file ...]\n", prog);
            desc.print(std::cout);
            std::fflush(stdout);
            return EXIT_FAILURE;
        }

        po::notify(vm);

        if (!vm.contains("input-file"))
        {
            std::println("no input file(s)");
            std::fflush(stdout);
            return EXIT_FAILURE;
        }

        RunRS2Checks();
        std::fflush(stdout);
        return EXIT_SUCCESS;
    }
    catch (const std::exception& ex)
    {
        std::println("main: error: {}", ex.what());
        THROW_IF_DEBUGGING();
        return EXIT_FAILURE;
    }
    // Catch anything else that was unhandled.
    catch (...)
    {
        std::println("main: unhandled error");
        THROW_IF_DEBUGGING();
        return EXIT_FAILURE;
    }
}
