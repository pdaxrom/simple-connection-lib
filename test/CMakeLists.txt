# Test programs
set(TEST_PROGRAMS
    tcpclient
    tcpserver
    tcpclient-ws
    tcpserver-ws
    tcpclient-ws-comprehensive
    tcpserver-ws-comprehensive
    tcpsslclient
    tcpsslserver
    tcpsslclient-ws
    tcpsslserver-ws
    udpchat
    udpclient
    udpserver
    tcpclient-ipv6
    tcpserver-ipv6
    udpclient-ipv6
    udpserver-ipv6
)

# Create test programs
foreach(test_prog ${TEST_PROGRAMS})
    add_executable(${test_prog} ${test_prog}.c)
    target_link_libraries(${test_prog} PRIVATE simple_connection)
    target_include_directories(${test_prog} PRIVATE ../src)

    if(ENABLE_SSL)
        target_link_libraries(${test_prog} PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
endforeach()

# Install test programs (optional)
option(INSTALL_TESTS "Install test programs" OFF)
if(INSTALL_TESTS)
    foreach(test_prog ${TEST_PROGRAMS})
        install(TARGETS ${test_prog}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )
    endforeach()
endif()

# Add test target
enable_testing()

# Simple compilation test
add_test(NAME compilation_test
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --config $<CONFIGURATION>
)

# Add a basic functionality test if possible
# Note: Full integration tests would require running servers and clients
# which is complex in a CMake test environment