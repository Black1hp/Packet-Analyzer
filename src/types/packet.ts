export interface Packet {
  id: string;
  timestamp: Date;
  sourcePort: number;
  destinationPort: number;
  sourceIP: string;
  destinationIP: string;
  protocol: Protocol;
  size: number;
  isSuspicious: boolean;
  activity: Activity;
  application_protocol: Protocol;
  risk_level: RiskLevel;
  features: {
    duration: number;
    packet_rate: number;
    avg_size: number;
    is_encrypted: boolean;
    is_compressed: boolean;
  };
}

export type Protocol = 
  | 'HTTP' 
  | 'HTTPS' 
  | 'SSH' 
  | 'FTP' 
  | 'SMTP' 
  | 'DNS' 
  | 'MDNS'
  | 'NETBIOS'
  | 'MULTICAST'
  | 'IPV6-UDP'
  | 'IPV6-TCP'
  | 'POP3' 
  | 'IMAP' 
  | 'MySQL' 
  | 'PostgreSQL' 
  | 'TCP' 
  | 'UDP' 
  | 'ICMP'
  | 'WebSocket'
  | 'Streaming'
  | 'VoIP'
  | 'Gaming'
  | 'RDP'
  | 'MSSQL'
  | 'MongoDB'
  | 'Redis'
  | 'UNKNOWN';

export type Activity =
  | 'VoIP Call'
  | 'VoIP Signaling'
  | 'Messaging'
  | 'File Transfer'
  | 'DNS Query'
  | 'Video Streaming'
  | 'Audio Streaming'
  | 'Gaming'
  | 'Database Activity'
  | 'Remote Desktop'
  | 'UNKNOWN';

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH';