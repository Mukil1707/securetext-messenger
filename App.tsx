
import React, { useState, useEffect, useCallback, useRef } from 'react';
import { User, AuthState, SecurityEvent, EncryptedMessage } from './types';
import * as crypto from './services/cryptoService';
import { apiService } from './services/apiService';
import { socketService } from './services/socketService';
import { SecurityDashboard } from './components/SecurityDashboard';

const App: React.FC = () => {
  const [authState, setAuthState] = useState<AuthState>({ user: null, isAuthenticated: false });
  const [logs, setLogs] = useState<SecurityEvent[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [activeRecipient, setActiveRecipient] = useState<User | null>(null);
  const [messages, setMessages] = useState<(EncryptedMessage & { decryptedContent?: string })[]>([]);
  const [inputText, setInputText] = useState('');
  const [isRegistering, setIsRegistering] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [p2pReady, setP2pReady] = useState(false);
  const [activeConnections, setActiveConnections] = useState<string[]>([]);

  const chatEndRef = useRef<HTMLDivElement>(null);

  const addLog = useCallback((type: SecurityEvent['type'], message: string, status: SecurityEvent['status'] = 'SUCCESS') => {
    setLogs(prev => [{
      id: Math.random().toString(36).substring(2, 11),
      timestamp: Date.now(),
      type,
      message,
      status
    }, ...prev].slice(0, 50));
  }, []);

  useEffect(() => {
    if (authState.isAuthenticated && authState.user) {
      socketService.init(authState.user, (id) => {
        setP2pReady(true);
        addLog('MESH_NET', `Node ID ${id} is broadcasting on mesh network.`);
      });

      const cleanupMessages = socketService.onMessage(async (msg) => {
        if (msg.type === 'CHAT') {
          if (authState.privateKey) {
            try {
              const aesKey = await crypto.decryptKeyWithRSA(msg.data.encryptedSessionKey, authState.privateKey);
              const decrypted = await crypto.decryptWithAES(msg.data.encryptedContent, aesKey, msg.data.iv);
              setMessages(prev => [...prev, { ...msg.data, decryptedContent: decrypted }]);
              addLog('INTEGRITY_CHECK', `Decrypted signal from ${msg.data.senderId}`);
            } catch (err) {
              addLog('DECRYPTION', 'Integrity violation in packet', 'ERROR');
            }
          }
        } else if (msg.type === 'IDENTITY_EXCHANGE') {
          addLog('AUTH', `Secure P2P tunnel built with ${msg.username}`);
          setActiveConnections(socketService.getActiveConnections());
        }
      });

      const cleanupErrors = socketService.onError((type, msg) => {
        addLog('MESH_NET', `P2P Stack: ${msg}`, 'ERROR');
      });

      const syncInterval = setInterval(async () => {
        const globalUsers = await apiService.getUsers();
        setUsers(globalUsers.filter(u => u.username !== authState.user?.username));
        setActiveConnections(socketService.getActiveConnections());
      }, 5000);

      return () => {
        cleanupMessages();
        cleanupErrors();
        clearInterval(syncInterval);
      };
    }
  }, [authState.isAuthenticated, authState.user, authState.privateKey, addLog]);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    const cleanUsername = username.trim();
    if (cleanUsername.length < 3) {
      setError("UID must be at least 3 characters.");
      setLoading(false);
      return;
    }
    if (password.length < 6) {
      setError("Keyphrase must be at least 6 characters.");
      setLoading(false);
      return;
    }

    try {
      if (isRegistering) {
        addLog('AUTH', 'Generating local RSA Identity...');
        const keyPair = await crypto.generateRSAKeyPair();
        const masterKey = await crypto.deriveKeyFromPassword(password, cleanUsername);
        const passwordHash = await crypto.computeHash(password);
        const protectedKey = await crypto.protectPrivateKey(keyPair.privateKey, masterKey);
        
        const newUser: User = { id: '', username: cleanUsername, publicKey: keyPair.publicKey };
        const result = await apiService.register(newUser, passwordHash, protectedKey.data, protectedKey.iv);
        
        addLog('AUTH', 'Identity published to Hybrid Vault.');
        setAuthState({ user: { ...newUser, id: result.id }, isAuthenticated: true, privateKey: keyPair.privateKey });
      } else {
        addLog('AUTH', 'Searching registry for UID...');
        const userData = await apiService.login(cleanUsername);
        const passwordHash = await crypto.computeHash(password);
        
        if (userData.passwordHash !== passwordHash) {
          throw new Error("INVALID_KEYPHRASE");
        }

        const masterKey = await crypto.deriveKeyFromPassword(password, cleanUsername);
        const privateKey = await crypto.recoverPrivateKey(userData.encryptedPriv, masterKey, userData.privIv);
        
        addLog('AUTH', 'Zero-knowledge session initialized.');
        setAuthState({ 
          user: { id: userData.id, username: userData.username, publicKey: userData.publicKey }, 
          isAuthenticated: true, 
          privateKey 
        });
      }
    } catch (err: any) {
      if (err.message === 'IDENTITY_EXISTS') {
        setError("This UID is already active. Try another.");
      } else if (err.message === 'NOT_FOUND') {
        setError("UID not found. Please Register first.");
      } else if (err.message === 'INVALID_KEYPHRASE') {
        setError("Incorrect Keyphrase for this UID.");
      } else {
        setError("Registry connection error. Try again.");
      }
      addLog('AUTH', `Auth failure: ${err.message}`, 'ERROR');
    } finally {
      setLoading(false);
    }
  };

  const sendMessage = async () => {
    if (!inputText.trim() || !activeRecipient || !authState.user) return;
    
    try {
      const sessionKey = await crypto.generateAESKey();
      const { ciphertext, iv } = await crypto.encryptWithAES(inputText, sessionKey);
      const encryptedSessionKey = await crypto.encryptKeyWithRSA(sessionKey, activeRecipient.publicKey);
      
      const msg: EncryptedMessage = {
        id: Math.random().toString(36).substring(2, 11),
        senderId: authState.user.username,
        recipientId: activeRecipient.username,
        isGroup: false,
        encryptedContent: ciphertext,
        encryptedSessionKey,
        iv,
        hmac: 'GCM-SECURE',
        timestamp: Date.now()
      };

      socketService.send(msg);
      setMessages(prev => [...prev, { ...msg, decryptedContent: inputText }]);
      setInputText('');
      addLog('ENCRYPTION', `Packet dispatched to node ${activeRecipient.username}`);
    } catch (e) {
      addLog('ENCRYPTION', 'Encryption layer error', 'ERROR');
    }
  };

  if (!authState.isAuthenticated) {
    return (
      <div className="min-h-screen bg-[#f8fafc] flex flex-col items-center justify-center p-6 font-mono text-black">
        <div className="w-full max-w-sm">
          <div className="text-center mb-10">
            <h1 className="text-6xl font-black italic tracking-tighter mb-2 uppercase">Shadow</h1>
            <p className="text-[10px] font-bold text-slate-400 uppercase tracking-[0.4em]">Encrypted Mesh Protocol</p>
          </div>
          
          <div className="bg-white p-8 border-4 border-black shadow-[12px_12px_0px_0px_rgba(0,0,0,1)]">
            <div className="flex justify-between items-center mb-8 border-b-4 border-black pb-4">
              <h2 className="text-xl font-black uppercase tracking-tighter">
                {isRegistering ? 'Register' : 'Login'}
              </h2>
              <div className="flex gap-1">
                <div className="w-2 h-2 rounded-full bg-black"></div>
                <div className="w-2 h-2 rounded-full bg-slate-200"></div>
              </div>
            </div>
            
            <form onSubmit={handleAuth} className="space-y-6">
              <div>
                <label className="block text-[10px] font-black uppercase mb-2 tracking-widest">Node Identifier (UID)</label>
                <input 
                  type="text" 
                  className="w-full px-5 py-4 border-4 border-black font-black text-sm outline-none focus:bg-slate-50 uppercase placeholder:lowercase"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="e.g. user_alpha"
                  required
                />
              </div>
              <div>
                <label className="block text-[10px] font-black uppercase mb-2 tracking-widest">Master Keyphrase</label>
                <input 
                  type="password" 
                  className="w-full px-5 py-4 border-4 border-black font-black text-sm outline-none focus:bg-slate-50"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  required
                />
              </div>
              
              {error && (
                <div className="p-4 bg-red-100 border-2 border-black">
                  <p className="text-[10px] font-bold text-red-700 uppercase text-center leading-tight">{error}</p>
                </div>
              )}

              <button 
                disabled={loading}
                className="w-full bg-black text-white py-5 font-black uppercase tracking-widest hover:bg-slate-800 transition-all disabled:opacity-50 active:translate-x-1 active:translate-y-1"
              >
                {loading ? 'Processing...' : (isRegistering ? 'Generate RSA Identity' : 'Authorize Session')}
              </button>
            </form>

            <button 
              onClick={() => { setIsRegistering(!isRegistering); setError(''); }}
              className="w-full mt-8 text-[10px] font-black uppercase tracking-widest text-slate-400 hover:text-black transition-colors"
            >
              {isRegistering ? '← Switch to Session Entry' : 'Create New Mesh Identity →'}
            </button>
          </div>
        </div>
        
        <div className="mt-12 max-w-xs text-center">
          <p className="text-[8px] font-bold text-slate-400 uppercase tracking-widest leading-loose">
            Shadow is currently using <span className="text-black">Hybrid Vault</span> (Cloud + Local Cache).
            Your private keys never leave this device unencrypted.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-screen bg-white font-mono text-black overflow-hidden border-8 border-black">
      {/* Sidebar */}
      <div className="w-80 border-r-8 border-black flex flex-col bg-white">
        <div className="p-8 border-b-8 border-black">
          <h1 className="text-4xl font-black italic tracking-tighter uppercase">Shadow</h1>
          <div className="mt-6 flex items-center gap-3 bg-slate-50 p-4 border-4 border-black">
            <div className={`w-3 h-3 rounded-full ${p2pReady ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}></div>
            <div className="overflow-hidden">
              <p className="text-[10px] font-black uppercase truncate">{authState.user?.username}</p>
              <p className="text-[8px] font-bold text-slate-400 uppercase tracking-widest">Protocol Active</p>
            </div>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-2">
          <p className="text-[9px] font-black uppercase text-slate-400 mb-4 ml-2 tracking-widest">Registry Nodes</p>
          {users.map((u) => (
            <button 
              key={u.id}
              onClick={() => {
                setActiveRecipient(u);
                socketService.connectToPeer(u.username);
              }}
              className={`w-full p-5 flex items-center gap-4 transition-all border-4 rounded-xl ${
                activeRecipient?.id === u.id
                  ? 'bg-black text-white border-black' 
                  : 'bg-white border-transparent hover:bg-slate-50 hover:border-slate-100'
              }`}
            >
              <div className="w-10 h-10 bg-slate-100 border-2 border-black flex items-center justify-center font-black text-black">
                {u.username.substring(0, 1).toUpperCase()}
              </div>
              <div className="text-left overflow-hidden">
                <div className="text-[11px] font-black uppercase truncate">{u.username}</div>
                <div className={`text-[8px] font-bold uppercase ${
                  activeConnections.includes(`ST-${u.username.toLowerCase()}`) ? 'text-green-500' : 'text-slate-400'
                }`}>
                  {activeConnections.includes(`ST-${u.username.toLowerCase()}`) ? 'Handshake established' : 'Searching mesh...'}
                </div>
              </div>
            </button>
          ))}
          {users.length === 0 && (
            <div className="p-10 text-center text-[9px] font-bold text-slate-300 uppercase tracking-widest mt-10">
              Scanning for active identities...
            </div>
          )}
        </div>
      </div>

      {/* Main Terminal */}
      <div className="flex-1 flex flex-col bg-[#fafafa] relative">
        {activeRecipient ? (
          <>
            <div className="p-8 border-b-8 border-black bg-white flex justify-between items-center sticky top-0 z-10">
              <div>
                <h2 className="text-3xl font-black uppercase italic tracking-tighter">{activeRecipient.username}</h2>
                <div className="flex items-center gap-2 mt-1">
                   <i className="fas fa-shield-halved text-[10px] text-green-600"></i>
                   <p className="text-[9px] font-bold uppercase text-slate-400 tracking-widest">AES-256-GCM Secure Channel</p>
                </div>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto p-10 space-y-8 scrollbar-hide">
              {messages.filter(m => 
                (m.senderId === authState.user?.username && m.recipientId === activeRecipient.username) ||
                (m.senderId === activeRecipient.username && m.recipientId === authState.user?.username)
              ).map((m) => (
                <div key={m.id} className={`flex ${m.senderId === authState.user?.username ? 'justify-end' : 'justify-start'}`}>
                  <div className={`max-w-[80%] ${m.senderId === authState.user?.username ? 'order-2' : ''}`}>
                    <div className={`p-6 border-4 border-black font-black text-xs uppercase rounded-2xl shadow-[6px_6px_0px_0px_rgba(0,0,0,0.05)] ${
                      m.senderId === authState.user?.username ? 'bg-black text-white' : 'bg-white text-black'
                    }`}>
                      {m.decryptedContent || '[PROTOCOL ERROR: ENCRYPTION MISMATCH]'}
                    </div>
                    <div className={`mt-3 text-[8px] font-bold text-slate-400 uppercase tracking-widest flex items-center gap-3 ${m.senderId === authState.user?.username ? 'justify-end' : ''}`}>
                      <span>{new Date(m.timestamp).toLocaleTimeString()}</span>
                      {m.senderId === authState.user?.username && <i className="fas fa-check-double text-black"></i>}
                    </div>
                  </div>
                </div>
              ))}
              <div ref={chatEndRef} />
            </div>

            <div className="p-8 bg-white border-t-8 border-black">
              <div className="flex gap-4">
                <input 
                  type="text"
                  className="flex-1 px-8 py-5 border-4 border-black font-black text-sm outline-none uppercase focus:bg-slate-50 transition-colors"
                  placeholder="Transmit secure signal..."
                  value={inputText}
                  onChange={(e) => setInputText(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && sendMessage()}
                />
                <button 
                  onClick={sendMessage}
                  className="bg-black text-white px-10 font-black uppercase tracking-widest hover:bg-slate-800 active:translate-x-1 active:translate-y-1 transition-all"
                >
                  SEND
                </button>
              </div>
            </div>
          </>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center p-20 text-center bg-white">
            <div className="w-32 h-32 bg-slate-50 border-8 border-black flex items-center justify-center mb-10 shadow-[12px_12px_0px_0px_rgba(0,0,0,1)]">
               <i className="fas fa-satellite text-5xl"></i>
            </div>
            <h2 className="text-5xl font-black uppercase tracking-tighter mb-4 italic">Channel Standby</h2>
            <p className="max-w-xs text-[10px] font-bold uppercase text-slate-400 tracking-[0.2em] leading-loose">
              Establish a cryptographic tunnel by selecting a node from the mesh registry.
            </p>
          </div>
        )}
      </div>

      {/* Security Audit Trail */}
      <div className="w-96 border-l-8 border-black p-8 bg-white hidden xl:flex flex-col">
        <SecurityDashboard logs={logs} />
      </div>
    </div>
  );
};

export default App;
