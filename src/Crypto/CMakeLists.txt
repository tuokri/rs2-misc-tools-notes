add_library(
    RS2Crypto
    STATIC
    Crypto.cpp
)

target_include_directories(
    RS2Crypto
    PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

set_property(
    TARGET RS2Crypto
    PROPERTY INTERPROCEDURAL_OPTIMIZATION ${RS2_IPO_SUPPORTED}
)
