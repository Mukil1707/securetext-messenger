
# SecureText Pro: Real-Time P2P Encrypted Messenger

This is a production-grade final-year project demonstrating Advanced Cryptography and Network Security principles using **Peer-to-Peer (P2P)** communication.

## How to test cross-device communication:
1.  Open the application on **Device A** (e.g., your laptop).
2.  Register with a username (e.g., `Alice`).
3.  Open the application on **Device B** (e.g., your smartphone).
4.  Register with a different username (e.g., `Bob`).
5.  On `Bob's` device, you will see `Alice` in the "Active Nodes" list.
6.  Click on the node to establish a secure P2P handshake and begin chatting.

## Core Security Stack:
-   **Identity**: RSA-2048 Asymmetric Keypairs.
-   **Session Privacy**: AES-256-GCM Symmetric Encryption.
-   **Transport**: WebRTC P2P Data Channels (via PeerJS).
-   **Key Derivation**: PBKDF2 with 100,000 iterations.
-   **Integrity**: SHA-256 Hashing for payload verification.

## Academic Value:
This project demonstrates:
- **Confidentiality**: Only the recipient can decrypt the message using their private RSA key.
- **Integrity**: Any bit-flip during transit results in an integrity check failure.
- **Authentication**: Users verify identities via RSA Public Key exchange.
- **Availability**: P2P avoids a single point of failure (central server).

---
*Senior Security Mentor*
