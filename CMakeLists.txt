# CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(tls13-hybrid C)

# Set WOLFSSL_ROOT to your wolfSSL source directory.
# Override on the command line: cmake -DWOLFSSL_ROOT=C:/path/to/wolfssl ..
if(NOT DEFINED WOLFSSL_ROOT)
    message(FATAL_ERROR
        "WOLFSSL_ROOT is not set. Pass it with -DWOLFSSL_ROOT=<path> "
        "pointing to your wolfSSL source directory.")
endif()

# Detect library path based on build type
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(WOLFSSL_ARCH "x64")
else()
    set(WOLFSSL_ARCH "x86")
endif()

set(WOLFSSL_LIB_DIR "${WOLFSSL_ROOT}/Debug/${WOLFSSL_ARCH}"
    CACHE PATH "Path to wolfssl.lib")

# Shared settings
include_directories(${WOLFSSL_ROOT} ${WOLFSSL_ROOT}/wolfssl)
link_directories(${WOLFSSL_LIB_DIR})
add_definitions(-DWOLFSSL_USER_SETTINGS)

# Server
add_executable(server server.c)
target_link_libraries(server wolfssl ws2_32 advapi32)

# Client
add_executable(client client.c)
target_link_libraries(client wolfssl ws2_32 advapi32)