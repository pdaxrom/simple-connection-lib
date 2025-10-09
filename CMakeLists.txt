cmake_minimum_required(VERSION 3.10)
project(simple-connection VERSION 1.0.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Add compiler warnings
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wpedantic)
endif()

# Platform-specific settings
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_definitions(-D_GNU_SOURCE)
endif()

# IPv6 support (enabled by default)
option(ENABLE_IPV6 "Enable IPv6 support" ON)
if(ENABLE_IPV6)
    include(CheckFunctionExists)
    include(CheckTypeSize)

    check_function_exists(getaddrinfo HAVE_GETADDRINFO)
    check_type_size("struct sockaddr_in6" SOCKADDR_IN6_SIZE)

    if(HAVE_GETADDRINFO)
        add_definitions(-DHAVE_GETADDRINFO)
    endif()

    if(SOCKADDR_IN6_SIZE GREATER 0)
        add_definitions(-DHAVE_IPV6)
    endif()
endif()

# SSL support (enabled by default)
option(ENABLE_SSL "Enable SSL/TLS support" ON)
if(ENABLE_SSL)
    find_package(OpenSSL REQUIRED)
    add_definitions(-DENABLE_SSL)
    include_directories(${OPENSSL_INCLUDE_DIR})
endif()

# Add subdirectories
add_subdirectory(src)

# Build tests by default
option(BUILD_TESTS "Build test programs" ON)
if(BUILD_TESTS)
    add_subdirectory(test)
endif()

# Install pkg-config file
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/simple-connection.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/simple-connection.pc
    @ONLY
)

install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/simple-connection.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)