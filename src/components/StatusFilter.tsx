import React from 'react';
import { Shield, AlertTriangle } from 'lucide-react';

interface StatusFilterProps {
  value: boolean;
  onChange: (value: boolean) => void;
}

export function StatusFilter({ value, onChange }: StatusFilterProps) {
  return (
    <select
      value={value ? 'suspicious' : 'all'}
      onChange={(e) => onChange(e.target.value === 'suspicious')}
      className="flex-shrink-0 w-48 rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
    >
      <option value="all">All Packets</option>
      <option value="suspicious">Suspicious Only</option>
    </select>
  );
}