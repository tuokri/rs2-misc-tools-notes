add_subdirectory(Crypto)
add_subdirectory(Safelist)

add_executable(
    RS2Tools
    ${CMAKE_CURRENT_SOURCE_DIR}/Main.cpp
)

target_link_libraries(
    RS2Tools
    PRIVATE
    RS2Crypto
    Boost::asio
    Boost::filesystem
    Boost::program_options
    Boost::system
)

target_include_directories(
    RS2Tools
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

set_property(
    TARGET RS2Tools
    PROPERTY INTERPROCEDURAL_OPTIMIZATION ${RS2_IPO_SUPPORTED}
)
