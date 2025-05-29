#!/bin/bash

# Stop all IDS components started by start.sh

echo "Stopping IDS System..."

# Check if PID file exists
if [ -f .running_pids ]; then
    # Read PIDs from file
    read -r SERVER_PID SURICATA_PID FRONTEND_PID < .running_pids
    
    # Stop the processes
    echo "Stopping Backend Server (PID: $SERVER_PID)..."
    kill $SERVER_PID 2>/dev/null || echo "Backend Server already stopped"
    
    echo "Stopping Suricata Integration (PID: $SURICATA_PID)..."
    kill $SURICATA_PID 2>/dev/null || echo "Suricata Integration already stopped"
    
    echo "Stopping Frontend (PID: $FRONTEND_PID)..."
    kill $FRONTEND_PID 2>/dev/null || echo "Frontend already stopped"
    
    # Remove PID file
    rm .running_pids
    
    echo "All components stopped successfully!"
else
    echo "No running components found."
fi
