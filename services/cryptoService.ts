
/**
 * SENIOR SECURITY ENGINEER NOTE:
 * We use the Web Crypto API for high-performance, hardware-accelerated crypto.
 */

export const bufferToBase64 = (buffer: ArrayBuffer): string => {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
};

export const base64ToBuffer = (base64: string): ArrayBuffer => {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
};

// 1. PBKDF2 for Password Hashing & Key Derivation
export const deriveKeyFromPassword = async (password: string, salt: string): Promise<CryptoKey> => {
  const encoder = new TextEncoder();
  const passwordKey = await window.crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: encoder.encode(salt),
      iterations: 100000,
      hash: "SHA-256",
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
};

// 2. RSA-2048 Key Generation
export const generateRSAKeyPair = async (): Promise<{ publicKey: string; privateKey: CryptoKey }> => {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );

  const exportedPublic = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
  return {
    publicKey: bufferToBase64(exportedPublic),
    privateKey: keyPair.privateKey
  };
};

// 3. Encrypt Private Key for Storage (Zero-Knowledge)
export const protectPrivateKey = async (privateKey: CryptoKey, masterKey: CryptoKey): Promise<{ data: string, iv: string }> => {
  const exported = await window.crypto.subtle.exportKey("pkcs8", privateKey);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    masterKey,
    exported
  );
  return { data: bufferToBase64(encrypted), iv: bufferToBase64(iv) };
};

// 4. Decrypt Private Key from Storage
export const recoverPrivateKey = async (encryptedData: string, masterKey: CryptoKey, iv: string): Promise<CryptoKey> => {
  const decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBuffer(iv) },
    masterKey,
    base64ToBuffer(encryptedData)
  );
  return await window.crypto.subtle.importKey(
    "pkcs8",
    decrypted,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["decrypt"]
  );
};

// 5. Symmetric Encryption (AES-GCM)
// Added missing generateAESKey function required for session keys
export const generateAESKey = async (): Promise<CryptoKey> => {
  return await window.crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  );
};

export const encryptWithAES = async (text: string, key: CryptoKey): Promise<{ ciphertext: string; iv: string }> => {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const encrypted = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(text)
  );
  return {
    ciphertext: bufferToBase64(encrypted),
    iv: bufferToBase64(iv)
  };
};

export const decryptWithAES = async (ciphertext: string, key: CryptoKey, iv: string): Promise<string> => {
  const decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBuffer(iv) },
    key,
    base64ToBuffer(ciphertext)
  );
  return new TextDecoder().decode(decrypted);
};

// 6. Asymmetric Key Exchange
export const encryptKeyWithRSA = async (aesKey: CryptoKey, publicKeyStr: string): Promise<string> => {
  const publicKey = await window.crypto.subtle.importKey(
    "spki",
    base64ToBuffer(publicKeyStr),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );
  const rawAesKey = await window.crypto.subtle.exportKey("raw", aesKey);
  const encrypted = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, rawAesKey);
  return bufferToBase64(encrypted);
};

export const decryptKeyWithRSA = async (encryptedKeyStr: string, privateKey: CryptoKey): Promise<CryptoKey> => {
  const decryptedRaw = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, base64ToBuffer(encryptedKeyStr));
  return await window.crypto.subtle.importKey("raw", decryptedRaw, "AES-GCM", true, ["encrypt", "decrypt"]);
};

export const computeHash = async (text: string): Promise<string> => {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hash = await window.crypto.subtle.digest("SHA-256", data);
  return bufferToBase64(hash);
};
