import React from 'react';
import { format } from 'date-fns';
import { AlertTriangle, Shield } from 'lucide-react';
import { Packet } from '../types/packet';
import clsx from 'clsx';

interface PacketTableProps {
  packets: Packet[];
}

export function PacketTable({ packets }: PacketTableProps) {
  return (
    <div className="overflow-x-auto rounded-lg border border-gray-200">
      <table className="min-w-full divide-y divide-gray-200">
        <thead className="bg-gray-50">
          <tr>
            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time</th>
            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source Port</th>
            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Dest Port</th>
            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source IP</th>
            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Dest IP</th>
            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol</th>
            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Size</th>
            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
          </tr>
        </thead>
        <tbody className="bg-white divide-y divide-gray-200">
          {packets.map((packet) => (
            <tr key={packet.id} className={clsx(
              'hover:bg-gray-50 transition-colors duration-150',
              packet.isSuspicious && 'bg-red-50 hover:bg-red-100'
            )}>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                {format(new Date(packet.timestamp), 'HH:mm:ss.SSS')}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{packet.sourcePort}</td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{packet.destinationPort}</td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{packet.sourceIP}</td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{packet.destinationIP}</td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                  {packet.protocol}
                </span>
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{packet.size} bytes</td>
              <td className="px-6 py-4 whitespace-nowrap text-sm">
                {packet.isSuspicious ? (
                  <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                    <AlertTriangle className="w-4 h-4 mr-1" />
                    Suspicious
                  </span>
                ) : (
                  <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                    <Shield className="w-4 h-4 mr-1" />
                    Normal
                  </span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}