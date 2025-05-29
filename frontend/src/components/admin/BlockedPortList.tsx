import React from 'react';
import { X } from 'lucide-react';
import { BlockedPort } from '../../types/admin';

interface BlockedPortListProps {
  blockedPorts: BlockedPort[];
  onRemove: (port: number, type: 'source' | 'destination') => void;
}

export function BlockedPortList({ blockedPorts, onRemove }: BlockedPortListProps) {
  if (blockedPorts.length === 0) {
    return (
      <div className="text-sm text-gray-500 italic">
        No blocked ports yet
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {blockedPorts.map((blockedPort) => (
        <div
          key={`${blockedPort.port}-${blockedPort.type}`}
          className="flex items-center justify-between bg-orange-50 px-3 py-2 rounded-md"
        >
          <div>
            <span className="text-sm font-medium text-orange-800">
              {blockedPort.port} ({blockedPort.type})
            </span>
            <span className="ml-2 text-xs text-gray-500">
              Added: {new Date(blockedPort.timestamp).toLocaleString()}
            </span>
          </div>
          <button
            onClick={() => onRemove(blockedPort.port, blockedPort.type)}
            className="text-orange-600 hover:text-orange-800 transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      ))}
    </div>
  );
}