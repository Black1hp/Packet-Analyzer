import React from 'react';
import { format } from 'date-fns';
import { AlertTriangle, Shield, Activity, Radio, Download, Database, Monitor } from 'lucide-react';
import { Packet } from '../types/packet';
import clsx from 'clsx';

interface PacketTableProps {
  packets: Packet[];
}

const getActivityIcon = (activity: string) => {
  switch (activity) {
    case 'VoIP Call':
    case 'VoIP Signaling':
      return <Radio className="w-4 h-4" />;
    case 'File Transfer':
      return <Download className="w-4 h-4" />;
    case 'Database Activity':
      return <Database className="w-4 h-4" />;
    case 'Remote Desktop':
      return <Monitor className="w-4 h-4" />;
    default:
      return <Activity className="w-4 h-4" />;
  }
};

const getRiskLevelColor = (risk: string) => {
  switch (risk) {
    case 'HIGH':
      return 'bg-red-100 text-red-800';
    case 'MEDIUM':
      return 'bg-yellow-100 text-yellow-800';
    case 'LOW':
      return 'bg-green-100 text-green-800';
    default:
      return 'bg-gray-100 text-gray-800';
  }
};

export function PacketTable({ packets }: PacketTableProps) {
  return (
    <div className="relative overflow-x-auto">
      <div className="w-full rounded-lg border border-gray-200 overflow-hidden">
        <div className="max-h-[calc(100vh-300px)] overflow-auto">
          <table className="w-full divide-y divide-gray-200">
            <thead className="bg-gray-50 sticky top-0 z-10">
              <tr>
                <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">Time</th>
                <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">Source Port</th>
                <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">Dest Port</th>
                <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">Source IP</th>
                <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">Dest IP</th>
                <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">Protocol</th>
                <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">Activity</th>
                <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">Size</th>
                <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">Risk Level</th>
                <th scope="col" className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">Status</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {packets.map((packet) => (
                <tr 
                  key={packet.id} 
                  className={clsx(
                    'hover:bg-gray-50 transition-colors duration-150',
                    packet.isSuspicious && 'bg-red-50 hover:bg-red-100'
                  )}
                >
                  <td className="px-4 py-3 text-sm text-gray-900 whitespace-nowrap">
                    {format(new Date(packet.timestamp), 'HH:mm:ss.SSS')}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-900 whitespace-nowrap">{packet.sourcePort}</td>
                  <td className="px-4 py-3 text-sm text-gray-900 whitespace-nowrap">{packet.destinationPort}</td>
                  <td className="px-4 py-3 text-sm text-gray-900 whitespace-nowrap">{packet.sourceIP}</td>
                  <td className="px-4 py-3 text-sm text-gray-900 whitespace-nowrap">{packet.destinationIP}</td>
                  <td className="px-4 py-3 text-sm whitespace-nowrap">
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                      {packet.application_protocol || packet.protocol}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm whitespace-nowrap">
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                      {getActivityIcon(packet.activity)}
                      <span className="ml-1">{packet.activity}</span>
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm whitespace-nowrap">
                    <div>
                      {packet.size} bytes
                      {packet.features?.packet_rate > 0 && (
                        <span className="text-xs text-gray-500 block">
                          {packet.features.packet_rate.toFixed(1)} pkts/s
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm whitespace-nowrap">
                    <span className={clsx(
                      'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium',
                      getRiskLevelColor(packet.risk_level)
                    )}>
                      {packet.risk_level}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm whitespace-nowrap">
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
      </div>
    </div>
  );
}