
import { EncryptedMessage, User } from '../types';

declare var Peer: any;

export type ProtocolMessage = 
  | { type: 'CHAT'; data: EncryptedMessage }
  | { type: 'IDENTITY_EXCHANGE'; publicKey: string; username: string };

type MessageHandler = (msg: ProtocolMessage) => void;
type ErrorHandler = (errorType: string, message: string) => void;

class SocketService {
  private peer: any = null;
  private connections: Map<string, any> = new Map();
  private handlers: Set<MessageHandler> = new Set();
  private errorHandlers: Set<ErrorHandler> = new Set();
  public myId: string = '';
  private myUser: User | null = null;
  public isOnline: boolean = false;

  // Reconnection state
  private reconnectDelay = 1000;
  private readonly maxReconnectDelay = 30000;
  private reconnectTimeout: any = null;
  private isDestroyed = false;

  /**
   * Starts the secure P2P node.
   * Utilizes global STUN servers to bypass NAT and Firewalls.
   */
  init(user: User, onReady: (id: string) => void) {
    if (this.peer && !this.peer.destroyed) return;
    
    this.isDestroyed = false;
    this.myUser = user;
    this.myId = `ST-${user.username.trim().toLowerCase()}`;
    
    const config = {
      config: {
        'iceServers': [
          { url: 'stun:stun.l.google.com:19302' },
          { url: 'stun:stun1.l.google.com:19302' },
          { url: 'stun:stun2.l.google.com:19302' },
          { url: 'stun:stun3.l.google.com:19302' },
          { url: 'stun:stun4.l.google.com:19302' }
        ],
        'iceCandidatePoolSize': 10
      },
      debug: 1
    };

    this.createPeer(onReady, config);
  }

  private createPeer(onReady: (id: string) => void, config: any) {
    this.peer = new Peer(this.myId, config);

    this.peer.on('open', (id: string) => {
      this.isOnline = true;
      this.reconnectDelay = 1000; // Reset delay on successful connection
      onReady(id);
    });

    this.peer.on('connection', (conn: any) => {
      this.setupConnection(conn);
    });

    this.peer.on('error', (err: any) => {
      let msg = err.message;
      let status = 'ERROR';
      
      switch (err.type) {
        case 'peer-unavailable':
          msg = `Node ${err.message.replace('ST-', '')} is currently offline or unreachable.`;
          // Cleanup stale connection if it exists
          this.connections.delete(err.message);
          break;
        case 'webrtc':
          msg = "P2P Handshake failed. This is likely due to a restrictive firewall or symmetric NAT. Try a different network.";
          break;
        case 'network':
          msg = "Peer server connection lost. Retrying...";
          this.handleReconnect();
          break;
        case 'unavailable-id':
          msg = "This Node ID is already active on the mesh. Is another session open?";
          break;
        default:
          msg = `Protocol Error: ${err.type} - ${err.message}`;
      }
      
      this.errorHandlers.forEach(h => h(err.type, msg));
    });

    this.peer.on('disconnected', () => {
      this.isOnline = false;
      this.handleReconnect();
    });

    this.peer.on('close', () => {
      this.isOnline = false;
      if (!this.isDestroyed) {
        this.handleReconnect();
      }
    });
  }

  private handleReconnect() {
    if (this.reconnectTimeout) return;

    this.reconnectTimeout = setTimeout(() => {
      console.log(`Attempting mesh reconnection... Delay: ${this.reconnectDelay}ms`);
      if (this.peer && this.peer.disconnected && !this.peer.destroyed) {
        this.peer.reconnect();
      } else if (!this.peer || this.peer.destroyed) {
        // Full recreate if destroyed
        if (this.myUser) {
          this.init(this.myUser, () => {});
        }
      }
      
      this.reconnectTimeout = null;
      // Exponential backoff
      this.reconnectDelay = Math.min(this.reconnectDelay * 1.5, this.maxReconnectDelay);
    }, this.reconnectDelay);
  }

  private setupConnection(conn: any) {
    // Prevent duplicate connection handlers
    if (this.connections.has(conn.peer)) {
      const existing = this.connections.get(conn.peer);
      if (existing.open) return;
    }

    conn.on('open', () => {
      if (this.myUser) {
        conn.send({
          type: 'IDENTITY_EXCHANGE',
          publicKey: this.myUser.publicKey,
          username: this.myUser.username
        });
      }
      this.connections.set(conn.peer, conn);
    });

    conn.on('data', (data: ProtocolMessage) => {
      if (data.type === 'IDENTITY_EXCHANGE') {
        const peerId = `ST-${data.username.toLowerCase()}`;
        this.connections.set(peerId, conn);
      }
      this.handlers.forEach(h => h(data));
    });

    const cleanup = () => {
      this.connections.delete(conn.peer);
    };

    conn.on('close', cleanup);
    conn.on('error', cleanup);
  }

  /**
   * Manual trigger for a P2P handshake.
   */
  connectToPeer(targetUsername: string) {
    const peerId = `ST-${targetUsername.trim().toLowerCase()}`;
    if (peerId === this.myId) return;
    
    const existing = this.connections.get(peerId);
    if (existing && existing.open) return;

    if (!this.peer || this.peer.destroyed || !this.isOnline) {
      this.errorHandlers.forEach(h => h('offline', 'Cannot connect: Node is currently offline from mesh.'));
      return;
    }
    
    try {
      const conn = this.peer.connect(peerId, { 
        reliable: true,
        metadata: { sender: this.myUser?.username }
      });
      this.setupConnection(conn);
    } catch (e) {
      this.errorHandlers.forEach(h => h('connect-fail', 'Initialization of P2P channel failed.'));
    }
  }

  onMessage(handler: MessageHandler) {
    this.handlers.add(handler);
    return () => { this.handlers.delete(handler); };
  }

  onError(handler: ErrorHandler) {
    this.errorHandlers.add(handler);
    return () => { this.errorHandlers.delete(handler); };
  }

  getActiveConnections() {
    return Array.from(this.connections.entries())
      .filter(([_, conn]) => conn.open)
      .map(([id]) => id);
  }

  send(message: EncryptedMessage) {
    if (!this.isOnline) {
      this.errorHandlers.forEach(h => h('transport', 'Signal dropped: Node is offline.'));
      return;
    }

    const payload: ProtocolMessage = { type: 'CHAT', data: message };
    const targetPeerId = `ST-${message.recipientId.trim().toLowerCase()}`;
    
    let conn = this.connections.get(targetPeerId);
    
    if (!conn || !conn.open) {
      // Attempt auto-reconnect if sending and disconnected
      try {
        conn = this.peer.connect(targetPeerId, { reliable: true });
        this.setupConnection(conn);
        conn.on('open', () => conn.send(payload));
      } catch (e) {
        this.errorHandlers.forEach(h => h('send-fail', `Could not reach node ${message.recipientId}`));
      }
    } else {
      try {
        conn.send(payload);
      } catch (e) {
        this.connections.delete(targetPeerId);
        this.errorHandlers.forEach(h => h('send-fail', 'Transmission failed. Retrying...'));
        this.send(message); // One-time retry
      }
    }
  }

  destroy() {
    this.isDestroyed = true;
    if (this.reconnectTimeout) clearTimeout(this.reconnectTimeout);
    this.connections.forEach(conn => conn.close());
    this.connections.clear();
    if (this.peer) this.peer.destroy();
    this.isOnline = false;
  }
}

export const socketService = new SocketService();
