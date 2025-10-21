#include <exception>
#include <filesystem>
#include <iostream>
#include <print>

#include <boost/asio.hpp>
#include <boost/program_options.hpp>

#include "RS2Tools.hpp"

namespace
{

namespace po = boost::program_options;
namespace fs = std::filesystem;
namespace asio = boost::asio;

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

        // TODO: just find all .u files in the working dir in this case,
        if (!vm.contains("input-file"))
        {
            std::println("no input file(s)");
            std::fflush(stdout);
            return EXIT_FAILURE;
        }

        asio::io_context ioc;
        // ioc.run();

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
