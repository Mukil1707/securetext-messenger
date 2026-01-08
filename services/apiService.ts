
import { User } from '../types';

/**
 * GLOBAL & LOCAL HYBRID DISCOVERY SERVICE
 * This service manages identity publication. 
 * If the Cloud Registry (MockAPI) is unavailable, it uses LocalVault as a fallback.
 */
const CLOUD_URL = 'https://67bc8203ed715aa517300c3c.mockapi.io/api/v1/users'; 

// Local fallback storage key
const LOCAL_VAULT_KEY = 'shadow_net_local_registry';

export const apiService = {
  /**
   * Internal helper to get all known users (Cloud + Local)
   */
  async getAllUsersInternal(): Promise<any[]> {
    let cloudUsers: any[] = [];
    try {
      const res = await fetch(CLOUD_URL, { cache: 'no-store' });
      if (res.ok) {
        cloudUsers = await res.json();
      }
    } catch (e) {
      console.warn("Cloud Registry unreachable, using local cache.");
    }

    const localData = localStorage.getItem(LOCAL_VAULT_KEY);
    const localUsers = localData ? JSON.parse(localData) : [];
    
    // Merge and deduplicate by username
    const map = new Map();
    [...localUsers, ...cloudUsers].forEach(u => {
      if (u.username) map.set(u.username.toLowerCase().trim(), u);
    });
    
    return Array.from(map.values());
  },

  /**
   * Registers a new identity.
   */
  register: async (user: User, passwordHash: string, encryptedPriv: string, privIv: string) => {
    const normalizedInput = user.username.trim().toLowerCase();
    
    // 1. Check for collisions locally and in cloud
    const allUsers = await apiService.getAllUsersInternal();
    if (allUsers.find(u => u.username.toLowerCase().trim() === normalizedInput)) {
      throw new Error("IDENTITY_EXISTS");
    }

    const payload = {
      username: user.username.trim(),
      publicKey: user.publicKey,
      encryptedPriv,
      privIv,
      passwordHash,
      createdAt: Date.now()
    };

    // 2. Attempt Cloud Registration
    let cloudSuccess = false;
    let cloudId = '';
    try {
      const response = await fetch(CLOUD_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (response.ok) {
        const data = await response.json();
        cloudId = data.id;
        cloudSuccess = true;
      }
    } catch (e) {
      console.error("Cloud registration failed, falling back to LocalVault.");
    }

    // 3. Always save to Local Registry to ensure "it works" immediately
    const localData = localStorage.getItem(LOCAL_VAULT_KEY);
    const localUsers = localData ? JSON.parse(localData) : [];
    const localEntry = { ...payload, id: cloudId || `local_${Date.now()}` };
    localUsers.push(localEntry);
    localStorage.setItem(LOCAL_VAULT_KEY, JSON.stringify(localUsers));

    return localEntry;
  },

  /**
   * Restores an identity.
   */
  login: async (username: string) => {
    const allUsers = await apiService.getAllUsersInternal();
    const normalizedInput = username.trim().toLowerCase();
    const user = allUsers.find(u => u.username.toLowerCase().trim() === normalizedInput);
    
    if (!user) throw new Error("NOT_FOUND");
    return user;
  },

  /**
   * Lists nodes for discovery.
   */
  getUsers: async (): Promise<User[]> => {
    try {
      const all = await apiService.getAllUsersInternal();
      return all.map(u => ({
        id: u.id,
        username: u.username,
        publicKey: u.publicKey
      }));
    } catch (e) {
      return [];
    }
  }
};
