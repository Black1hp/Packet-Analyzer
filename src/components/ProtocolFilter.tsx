import React from 'react';
import { Protocol } from '../types/packet';

interface ProtocolFilterProps {
  value: Protocol | '';
  onChange: (protocol: Protocol | '') => void;
}

const protocols: Protocol[] = ['SSH', 'FTP', 'SMTP', 'HTTP', 'HTTPS', 'TCP', 'UDP', 'ICMP', 'DNS', 'POP3', 'IMAP', 'MySQL', 'PostgreSQL'];

export function ProtocolFilter({ value, onChange }: ProtocolFilterProps) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value as Protocol | '')}
      className="block w-48 rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
    >
      <option value="">All Protocols</option>
      {protocols.map((protocol) => (
        <option key={protocol} value={protocol}>
          {protocol}
        </option>
      ))}
    </select>
  );
}