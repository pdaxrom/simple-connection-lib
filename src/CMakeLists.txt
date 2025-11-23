# Library sources
set(LIB_SOURCES
    tcp.c
    udp.c
    base64.c
    getrandom.c
    errors.c
    platform.c
    socket_utils.c
    sha1.c
)

set(LIB_HEADERS
    tcp.h
    udp.h
    base64.h
    getrandom.h
    errors.h
    platform.h
    socket_utils.h
    sha1.h
)

# Create the library
add_library(simple_connection ${LIB_SOURCES} ${LIB_HEADERS})

# Set library version
set_target_properties(simple_connection PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# Include directories
target_include_directories(simple_connection
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include/simple-connection>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link OpenSSL if enabled
if(ENABLE_SSL)
    target_link_libraries(simple_connection PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

# Install library
install(TARGETS simple_connection
    EXPORT simple_connectionTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION include
)

# Install headers
install(FILES tcp.h udp.h errors.h
    DESTINATION include/simple-connection
)

# Export targets
install(EXPORT simple_connectionTargets
    FILE simple_connectionTargets.cmake
    NAMESPACE simple_connection::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/simple_connection
)

# Create and install config files
include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/simple_connectionConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/simple_connectionConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/simple_connectionConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/simple_connection
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/simple_connectionConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/simple_connectionConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/simple_connection
)
