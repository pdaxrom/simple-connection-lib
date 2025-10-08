#!/bin/bash

# WebSocket Comprehensive Test Runner
# This script runs the comprehensive WebSocket tests

echo "Running WebSocket Comprehensive Tests"
echo "====================================="

# Build the project first
echo "Building project..."
cd ..
make clean && make
if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi
cd test

echo "Starting WebSocket server test in background..."
./tcpserver-ws-comprehensive &
SERVER_PID=$!

# Wait a moment for server to start
sleep 2

echo "Running WebSocket client test..."
./tcpclient-ws-comprehensive

# Wait for server to finish
wait $SERVER_PID

echo "Tests completed!"
echo "=================="
echo "Check the output above for test results."
echo "Look for ✓ (passed) and ✗ (failed) indicators."