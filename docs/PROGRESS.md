# EchoMesh Project Progress

## DONE
- [Relay] Peer-to-peer routing with session ID rewriting.
- [Relay] Disconnect cleanup and reconnect overwrite logic.
- [Relay] Integration tests for routing, concurrent peers, and malformed connections.
- [E2EE] Authenticated client-to-client encryption (X25519 + ChaCha20Poly1305).
- [E2EE] Replay protection with timestamp validation (5-minute window).
- [E2EE] Unit tests for tampering, wrong keys, and wire stability.
- [Secrets] Removed plaintext token leak from relay logs.
- [Secrets] Verified redaction of sensitive fields in Debug/Display.
- [Storage] Encrypted local storage (XChaCha20Poly1305 field-level).
- [Storage] Tests for persistence, wrong-key, and corrupted payloads.
- [Async] Audit of worker shutdown logic (using broadcast channels).
- [Transports] BLE transport out-of-order fragment reassembly tested and verified.

## IN PROGRESS
- [CI] Matrix tests & interoperability checks.

## TODO
- [Transports] LAN transport reconnect/framing verification.
- [Security] Memory zeroization for sensitive buffers (IdentityKeyPair).

## Known Issues
- Relay registry cleanup could be more aggressive on idle.

## Architectural Decisions
- Dual-DH for E2EE: Ephemeral + Static DH ensures relay cannot forge sender identity.
- Fixed 1420B wire frame: Defeats packet-length analysis.
- Pseudo-TLS: Camouflages initial handshake as HTTPS.

## Next Step
- Final verification of CI and cross-platform tests.
