#!/bin/bash

# Start all IDS components with a single script
# This script starts the backend server, Suricata integration, and frontend

echo "Starting IDS System..."

# Create logs directory if it doesn't exist
mkdir -p logs

# Start the backend server
echo "Starting Backend Server..."
cd "$(dirname "$0")"
python3 backend/server.py > logs/server.log 2>&1 &
SERVER_PID=$!
echo "Backend Server started with PID: $SERVER_PID"

# Wait a moment for the server to initialize
sleep 2

# Start Suricata integration
echo "Starting Suricata Integration..."
python3 backend/suricata_integration.py > logs/suricata.log 2>&1 &
SURICATA_PID=$!
echo "Suricata Integration started with PID: $SURICATA_PID"

# Start the frontend
echo "Starting Frontend..."
cd frontend
npm run dev > ../logs/frontend.log 2>&1 &
FRONTEND_PID=$!
echo "Frontend started with PID: $FRONTEND_PID"

echo "All components started successfully!"
echo "To view logs, check the logs directory"
echo "To stop all components, run: ./stop.sh"

# Save PIDs to file for stop script
cd ..
echo "$SERVER_PID $SURICATA_PID $FRONTEND_PID" > .running_pids

echo "IDS is now running!"
