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
}

export type Protocol = 
  | 'HTTP' 
  | 'HTTPS' 
  | 'SSH' 
  | 'FTP' 
  | 'SMTP' 
  | 'DNS' 
  | 'POP3' 
  | 'IMAP' 
  | 'MySQL' 
  | 'PostgreSQL' 
  | 'TCP' 
  | 'UDP' 
  | 'ICMP'
  | 'UNKNOWN';