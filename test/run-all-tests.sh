#!/bin/bash

# Comprehensive Connection Test Suite
# Tests TCP/UDP IPv4, IPv6, SSL, and WebSocket connections

echo "Running Comprehensive Connection Test Suite"
echo "==========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASSED_TESTS=0
FAILED_TESTS=0

# Function to run a test
run_test() {
    local test_name="$1"
    local server_cmd="$2"
    local client_cmd="$3"
    local expected_output="$4"

    echo -e "\n${YELLOW}Running $test_name test...${NC}"

    # Start server in background
    eval "$server_cmd" &
    SERVER_PID=$!

    # Wait for server to start
    sleep 1

    # Run client and capture output
    CLIENT_OUTPUT=$(eval "$client_cmd" 2>&1)
    CLIENT_EXIT_CODE=$?

    # Wait for server to finish
    wait $SERVER_PID 2>/dev/null
    SERVER_EXIT_CODE=$?

    # Check results
    if [ $CLIENT_EXIT_CODE -eq 0 ] && [ $SERVER_EXIT_CODE -eq 0 ]; then
        if [ -n "$expected_output" ]; then
            if echo "$CLIENT_OUTPUT" | grep -q "$expected_output"; then
                echo -e "${GREEN}✓ $test_name test PASSED${NC}"
                ((PASSED_TESTS++))
            else
                echo -e "${RED}✗ $test_name test FAILED - Expected output not found${NC}"
                echo "Client output: $CLIENT_OUTPUT"
                ((FAILED_TESTS++))
            fi
        else
            echo -e "${GREEN}✓ $test_name test PASSED${NC}"
            ((PASSED_TESTS++))
        fi
    else
        echo -e "${RED}✗ $test_name test FAILED - Exit codes: client=$CLIENT_EXIT_CODE, server=$SERVER_EXIT_CODE${NC}"
        echo "Client output: $CLIENT_OUTPUT"
        ((FAILED_TESTS++))
    fi
}

# Build the project first
echo "Building project..."
cd ..
if command -v cmake >/dev/null 2>&1; then
    # Use CMake build
    mkdir -p build && cd build
    cmake .. && make
    if [ $? -ne 0 ]; then
        echo -e "${RED}CMake build failed!${NC}"
        exit 1
    fi
    cd ../test
    TEST_PREFIX="../build/test/"
else
    # Fallback to autotools
    make clean && make
    if [ $? -ne 0 ]; then
        echo -e "${RED}Autotools build failed!${NC}"
        exit 1
    fi
    cd test
    TEST_PREFIX="./"
fi

# Test 1: TCP IPv4
run_test "TCP IPv4" "${TEST_PREFIX}tcpserver" "${TEST_PREFIX}tcpclient" "Hello client"

# Test 2: TCP IPv6
run_test "TCP IPv6" "${TEST_PREFIX}tcpserver-ipv6" "${TEST_PREFIX}tcpclient-ipv6" "Hello IPv6 client"

# Test 3: UDP IPv4
run_test "UDP IPv4" "${TEST_PREFIX}udpserver" "${TEST_PREFIX}udpclient" "Hello client"

# Test 4: UDP IPv6
run_test "UDP IPv6" "${TEST_PREFIX}udpserver-ipv6" "${TEST_PREFIX}udpclient-ipv6" "Hello UDP IPv6 client"

# Test 5: TCP SSL
run_test "TCP SSL" "${TEST_PREFIX}tcpsslserver" "${TEST_PREFIX}tcpsslclient" "Hello client"

# Test 6: WebSocket
run_test "WebSocket" "${TEST_PREFIX}tcpserver-ws-comprehensive" "${TEST_PREFIX}tcpclient-ws-comprehensive" "WebSocket client test completed"

# Summary
echo -e "\n${YELLOW}Test Summary:${NC}"
echo "=============="
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
echo -e "${RED}Failed: $FAILED_TESTS${NC}"

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "\n${GREEN}All tests passed! ✓${NC}"
    exit 0
else
    echo -e "\n${RED}Some tests failed! ✗${NC}"
    exit 1
fi