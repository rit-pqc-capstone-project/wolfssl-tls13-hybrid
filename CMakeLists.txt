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

# Include wolfSSL headers
include_directories(${WOLFSSL_ROOT} ${WOLFSSL_ROOT}/wolfssl)

if(ANDROID)
    # ---- Android cross-compilation ----
    # WOLFSSL_LIB_DIR should point to where libwolfssl.so was built
    set(WOLFSSL_LIB_DIR "${WOLFSSL_ROOT}/build-android"
        CACHE PATH "Path to libwolfssl.so")

    # Find the shared library
    find_library(WOLFSSL_LIB wolfssl PATHS ${WOLFSSL_LIB_DIR} NO_DEFAULT_PATH)
    if(NOT WOLFSSL_LIB)
        # Fall back to direct path
        set(WOLFSSL_LIB "${WOLFSSL_LIB_DIR}/libwolfssl.so")
    endif()

    # Include the generated options header from the Android build
    include_directories(${WOLFSSL_LIB_DIR})

    # Server
    add_executable(server server.c)
    target_link_libraries(server ${WOLFSSL_LIB})

    # Client
    add_executable(client client.c)
    target_link_libraries(client ${WOLFSSL_LIB})

elseif(WIN32)
    # ---- Windows build ----
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(WOLFSSL_ARCH "x64")
    else()
        set(WOLFSSL_ARCH "x86")
    endif()

    set(WOLFSSL_LIB_DIR "${WOLFSSL_ROOT}/Debug/${WOLFSSL_ARCH}"
        CACHE PATH "Path to wolfssl.lib")

    link_directories(${WOLFSSL_LIB_DIR})
    add_definitions(-DWOLFSSL_USER_SETTINGS)

    # Server
    add_executable(server server.c)
    target_link_libraries(server wolfssl ws2_32 advapi32)

    # Client
    add_executable(client client.c)
    target_link_libraries(client wolfssl ws2_32 advapi32)

else()
    # ---- Linux / Raspberry Pi / POSIX ----
    find_library(WOLFSSL_LIB wolfssl)
    if(NOT WOLFSSL_LIB)
        message(FATAL_ERROR "libwolfssl not found. Install wolfSSL or set WOLFSSL_LIB_DIR.")
    endif()

    # Server
    add_executable(server server.c)
    target_link_libraries(server ${WOLFSSL_LIB})

    # Client
    add_executable(client client.c)
    target_link_libraries(client ${WOLFSSL_LIB})

endif()