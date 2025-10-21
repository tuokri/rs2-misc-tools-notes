find_package(doctest CONFIG REQUIRED)

add_executable(
    TestCrypto
    TestCrypto.cpp
)

target_link_libraries(
    TestCrypto
    PRIVATE
    doctest::doctest
)

add_test(
    NAME TestCrypto
    COMMAND TestCrypto
)
