import { useState, useEffect } from 'react';
import { socket } from '../utils/socket';
import { BlockedIP, BlockedPort } from '../types/admin';

export function useAdmin() {
  const [blockedIPs, setBlockedIPs] = useState<BlockedIP[]>([]);
  const [blockedPorts, setBlockedPorts] = useState<BlockedPort[]>([]);

  useEffect(() => {
    socket.on('blockedIPs', (ips: BlockedIP[]) => {
      setBlockedIPs(ips);
    });

    socket.on('blockedPorts', (ports: BlockedPort[]) => {
      setBlockedPorts(ports);
    });

    // Request initial data
    socket.emit('getBlockedIPs');
    socket.emit('getBlockedPorts');

    return () => {
      socket.off('blockedIPs');
      socket.off('blockedPorts');
    };
  }, []);

  const addBlockedIP = (ip: string) => {
    socket.emit('addBlockedIP', ip);
  };

  const removeBlockedIP = (ip: string) => {
    socket.emit('removeBlockedIP', ip);
  };

  const addBlockedPort = (port: number, type: 'source' | 'destination') => {
    socket.emit('addBlockedPort', { port, type });
  };

  const removeBlockedPort = (port: number, type: 'source' | 'destination') => {
    socket.emit('removeBlockedPort', { port, type });
  };

  return {
    blockedIPs,
    blockedPorts,
    addBlockedIP,
    removeBlockedIP,
    addBlockedPort,
    removeBlockedPort,
  };
}