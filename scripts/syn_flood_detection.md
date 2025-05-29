# SYN Flood Attack Detection Module

This module extends the IDS capabilities to detect SYN Flood attacks, a common form of DDoS attack.

## What is a SYN Flood Attack?

A SYN Flood attack is a form of denial-of-service attack in which an attacker sends a succession of SYN requests to a target's system, but never completes the handshake. This causes half-open connections that consume server resources until they time out.

## Implementation

Add the following code to `backend/server.py` to implement basic SYN Flood detection:

```python
def detect_syn_flood(packets, threshold=100, time_window=5):
    """
    Detect potential SYN flood attacks by monitoring SYN packet frequency
    
    Args:
        packets: List of packet dictionaries
        threshold: Number of SYN packets that triggers an alert
        time_window: Time window in seconds to consider
    
    Returns:
        Boolean indicating if a SYN flood was detected
    """
    current_time = time.time()
    # Filter packets to only include SYN packets within the time window
    syn_packets = [p for p in packets if 
                  p.get('proto') == 'TCP' and 
                  p.get('tcp', {}).get('flags', '') == 'S' and
                  current_time - p.get('timestamp', 0) <= time_window]
    
    # Count SYN packets by source IP
    syn_counts = {}
    for packet in syn_packets:
        src_ip = packet.get('src_ip')
        if src_ip:
            syn_counts[src_ip] = syn_counts.get(src_ip, 0) + 1
    
    # Check if any IP exceeds the threshold
    for ip, count in syn_counts.items():
        if count > threshold:
            logger.warning(f"Possible SYN flood attack detected from {ip}: {count} SYN packets in {time_window}s")
            return True
    
    return False
```

## Testing

You can test this detection using the provided `syn_flood_attack.sh` script:

1. Make the script executable:
   ```
   chmod +x scripts/syn_flood_attack.sh
   ```

2. Edit the script to target your test system:
   ```
   TARGET_IP="192.168.1.10"  # Change to your target IP
   TARGET_PORT="80"          # Change to your target port
   ```

3. Run the script (requires sudo):
   ```
   sudo ./scripts/syn_flood_attack.sh
   ```

4. The IDS should detect the attack and generate an alert.

## Integration

The SYN flood detection can be integrated into the main monitoring loop in `server.py` by adding a call to the detection function and appropriate alert handling.
