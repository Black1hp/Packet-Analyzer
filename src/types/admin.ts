export interface BlockedIP {
  ip: string;
  timestamp: string;
}

export interface BlockedPort {
  port: number;
  type: 'source' | 'destination';
  timestamp: string;
}