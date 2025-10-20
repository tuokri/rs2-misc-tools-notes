add_subdirectory(Crypto)

add_executable(
    RS2Tools
    ${CMAKE_CURRENT_SOURCE_DIR}/Main.cpp
)

target_link_libraries(
    RS2Tools
    PRIVATE
    RS2Crypto
)

target_include_directories(
    RS2Tools
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
