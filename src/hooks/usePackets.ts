import { useState, useMemo, useEffect } from 'react';
import { io } from 'socket.io-client';
import { Packet, Protocol } from '../types/packet';

const socket = io('http://localhost:5000');

export function usePackets() {
  const [packets, setPackets] = useState<Packet[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedProtocol, setSelectedProtocol] = useState<Protocol | ''>('');
  const [showOnlySuspicious, setShowOnlySuspicious] = useState(false);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    socket.on('connect', () => {
      setIsConnected(true);
      console.log('Connected to packet stream');
    });

    socket.on('disconnect', () => {
      setIsConnected(false);
      console.log('Disconnected from packet stream');
    });

    // Handle individual packets
    socket.on('new_packet', (newPacket: Packet) => {
      console.log('Received new packet:', newPacket);
      setPackets(prev => [newPacket, ...prev].slice(0, 100));
    });

    // Also keep the batch handler for backward compatibility
    socket.on('packet_batch', (newPackets: Packet[]) => {
      console.log('Received packet batch:', newPackets.length);
      setPackets(prev => [...newPackets, ...prev].slice(0, 100));
    });

    return () => {
      socket.off('connect');
      socket.off('disconnect');
      socket.off('new_packet');
      socket.off('packet_batch');
    };
  }, []);

  const filteredPackets = useMemo(() => {
    return packets.filter(packet => {
      const matchesSearch = searchTerm === '' || 
        packet.sourceIP.includes(searchTerm) || 
        packet.destinationIP.includes(searchTerm);
      
      const matchesProtocol = selectedProtocol === '' || 
        packet.protocol === selectedProtocol;

      const matchesSuspicious = !showOnlySuspicious || packet.isSuspicious;

      return matchesSearch && matchesProtocol && matchesSuspicious;
    });
  }, [packets, searchTerm, selectedProtocol, showOnlySuspicious]);

  return {
    packets: filteredPackets,
    searchTerm,
    setSearchTerm,
    selectedProtocol,
    setSelectedProtocol,
    showOnlySuspicious,
    setShowOnlySuspicious,
    isConnected
  };
}