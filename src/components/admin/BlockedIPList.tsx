import React from 'react';
import { X } from 'lucide-react';
import { BlockedIP } from '../../types/admin';

interface BlockedIPListProps {
  blockedIPs: BlockedIP[];
  onRemove: (ip: string) => void;
}

export function BlockedIPList({ blockedIPs, onRemove }: BlockedIPListProps) {
  if (blockedIPs.length === 0) {
    return (
      <div className="text-sm text-gray-500 italic">
        No blocked IPs yet
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {blockedIPs.map((blockedIP) => (
        <div
          key={blockedIP.ip}
          className="flex items-center justify-between bg-red-50 px-3 py-2 rounded-md"
        >
          <div>
            <span className="text-sm font-medium text-red-800">{blockedIP.ip}</span>
            <span className="ml-2 text-xs text-gray-500">
              Added: {new Date(blockedIP.timestamp).toLocaleString()}
            </span>
          </div>
          <button
            onClick={() => onRemove(blockedIP.ip)}
            className="text-red-600 hover:text-red-800 transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      ))}
    </div>
  );
}