
export interface User {
  id: string;
  username: string;
  publicKey: string; // Base64 RSA Public Key
}

export interface Group {
  id: string;
  name: string;
  members: string[]; // List of usernames
}

export interface EncryptedMessage {
  id: string;
  senderId: string;
  recipientId: string; // Can be a username or a Room ID
  isGroup: boolean;
  encryptedContent: string;
  encryptedSessionKey: string;
  iv: string;
  hmac: string;
  timestamp: number;
}

export interface SecurityEvent {
  id: string;
  timestamp: number;
  type: 'ENCRYPTION' | 'DECRYPTION' | 'KEY_EXCHANGE' | 'INTEGRITY_CHECK' | 'AUTH' | 'MESH_NET';
  message: string;
  status: 'SUCCESS' | 'WARNING' | 'ERROR';
}

export interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  privateKey?: CryptoKey;
}
