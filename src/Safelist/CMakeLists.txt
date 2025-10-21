add_library(
    RS2Safelist
    STATIC
    Safelist.cpp
)

target_include_directories(
    RS2Safelist
    PUBLIC
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(
    RS2Safelist
    PRIVATE
    Boost::hash2
)

set_property(
    TARGET RS2Safelist
    PROPERTY INTERPROCEDURAL_OPTIMIZATION ${RS2_IPO_SUPPORTED}
)
