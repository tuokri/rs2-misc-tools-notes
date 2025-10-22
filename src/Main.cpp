#include <exception>
#include <filesystem>
#include <iostream>
#include <print>

#include "RS2Tools.hpp"
#include "Crypto/Crypto.hpp"
#include "Safelist/Safelist.hpp"

#include <boost/asio.hpp>
#include <boost/program_options.hpp>

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

auto process(const std::vector<fs::path>& files) -> asio::awaitable<void>
{
    co_return;
}

} // namespace

int main(int argc, char** argv)
{
    try
    {
        po::options_description desc("Options");
        const auto cwd = fs::current_path();
        auto outDir = cwd;
        desc.add_options()("help,h", "print the help message");
        desc.add_options()
        (
            "output,o",
            po::value<std::string>()->default_value("Safelist.mut"),
            "mutator safelist output filename"
        );

        po::options_description hidden("Hidden options");
        hidden.add_options()(
            "input-file",
            po::value<std::vector<std::string> >(),
            "input file(s)");

        po::options_description cmdline;
        cmdline.add(desc).add(hidden);

        po::positional_options_description p;
        p.add("input-file", -1);

        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv)
                  .options(cmdline)
                  .positional(p)
                  .run(),
                  vm);

        const auto& prog = fs::path(argv[0]).filename().string();

        if (vm.contains("help"))
        {
            std::println("Usage: {} [input-file ...]\n", prog);
            desc.print(std::cout);
            std::fflush(stdout);
            return EXIT_FAILURE;
        }

        po::notify(vm);

        std::vector<fs::path> files;
        if (vm.contains("input-file"))
        {
            for (const auto& file: vm["input-file"].as<std::vector<std::string> >())
            {
                const auto path = fs::path(file);
                files.emplace_back(path);
            }
        }
        else
        {
            for (const auto& entry: fs::directory_iterator(cwd))
            {
                if (entry.is_regular_file())
                {
                    if (entry.path().extension() == ".u")
                    {
                        files.emplace_back(entry.path());
                    }
                }
            }
        }

        asio::io_context ioc;

        asio::co_spawn(ioc, process(files));

        ioc.run();

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
        return EXIT_FAILURE
