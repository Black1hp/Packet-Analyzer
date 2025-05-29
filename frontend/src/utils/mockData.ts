import { Packet, Protocol } from '../types/packet';

const protocols: Protocol[] = ['SSH', 'FTP', 'SMTP', 'HTTP', 'TCP', 'UDP', 'ICMP', 'DNS'];

function generateRandomIP() {
  return Array(4).fill(0).map(() => Math.floor(Math.random() * 256)).join('.');
}

function generateRandomPort() {
  return Math.floor(Math.random() * 65535);
}

let packetId = 0;

export function generateMockPacket(): Packet {
  const isSuspicious = Math.random() < 0.1; // 10% chance of being suspicious
  
  return {
    id: String(packetId++),
    timestamp: new Date(),
    sourcePort: generateRandomPort(),
    destinationPort: generateRandomPort(),
    sourceIP: generateRandomIP(),
    destinationIP: generateRandomIP(),
    protocol: protocols[Math.floor(Math.random() * protocols.length)],
    size: Math.floor(Math.random() * 1500),
    isSuspicious
  };
}