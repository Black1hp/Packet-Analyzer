import React, { useState } from 'react';
import { Shield, AlertTriangle } from 'lucide-react';
import { BlockedIPList } from './BlockedIPList';
import { BlockedPortList } from './BlockedPortList';
import { useAdmin } from '../../hooks/useAdmin';

export function AdminPanel() {
  const [newIP, setNewIP] = useState('');
  const [newPort, setNewPort] = useState('');
  const [portType, setPortType] = useState<'source' | 'destination'>('source');
  
  const {
    blockedIPs,
    blockedPorts,
    addBlockedIP,
    removeBlockedIP,
    addBlockedPort,
    removeBlockedPort,
  } = useAdmin();

  const handleAddIP = (e: React.FormEvent) => {
    e.preventDefault();
    if (newIP) {
      addBlockedIP(newIP);
      setNewIP('');
    }
  };

  const handleAddPort = (e: React.FormEvent) => {
    e.preventDefault();
    if (newPort) {
      const port = parseInt(newPort, 10);
      if (!isNaN(port) && port > 0 && port <= 65535) {
        addBlockedPort(port, portType);
        setNewPort('');
      }
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-sm p-6">
      <h2 className="text-xl font-semibold text-gray-900 mb-6">Admin Control Panel</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* IP Blocking Section */}
        <div className="space-y-4">
          <div className="flex items-center space-x-2">
            <Shield className="h-5 w-5 text-red-600" />
            <h3 className="text-lg font-medium text-gray-900">Blocked IPs</h3>
          </div>
          
          <form onSubmit={handleAddIP} className="flex space-x-2">
            <input
              type="text"
              value={newIP}
              onChange={(e) => setNewIP(e.target.value)}
              placeholder="Enter IP address"
              className="flex-1 rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
            <button
              type="submit"
              className="bg-red-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2"
            >
              Block IP
            </button>
          </form>
          
          <BlockedIPList
            blockedIPs={blockedIPs}
            onRemove={removeBlockedIP}
          />
        </div>

        {/* Port Blocking Section */}
        <div className="space-y-4">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="h-5 w-5 text-orange-600" />
            <h3 className="text-lg font-medium text-gray-900">Blocked Ports</h3>
          </div>
          
          <form onSubmit={handleAddPort} className="flex space-x-2">
            <input
              type="number"
              value={newPort}
              onChange={(e) => setNewPort(e.target.value)}
              placeholder="Enter port number"
              min="1"
              max="65535"
              className="flex-1 rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
            <select
              value={portType}
              onChange={(e) => setPortType(e.target.value as 'source' | 'destination')}
              className="rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              <option value="source">Source</option>
              <option value="destination">Destination</option>
            </select>
            <button
              type="submit"
              className="bg-orange-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-orange-700 focus:outline-none focus:ring-2 focus:ring-orange-500 focus:ring-offset-2"
            >
              Block Port
            </button>
          </form>
          
          <BlockedPortList
            blockedPorts={blockedPorts}
            onRemove={removeBlockedPort}
          />
        </div>
      </div>
    </div>
  );
}