## [0.2.0] - 2026-05-04

- Binary encoding + service-set codecs (Read / Write / Browse / Call /
  HistoryRead / Subscription / MonitoredItems).
- SecureChannel framing with header-context-aware policy interface.
- Pure-Dart crypto primitives (SHA-256 / HMAC / AES / P_SHA256 / RSA-OAEP /
  RSA-PKCS1-v1.5 / RSA-PSS) and PEM / PKCS#1 / PKCS#8 / X.509 parsing.
- Security policies — Basic256Sha256, Aes128_Sha256_RsaOaep,
  Aes256_Sha256_RsaPss.
- WebSocket byte transport (`opc.ws://` / `opc.wss://`).

## [0.1.0] - 2026-04-28 - Initial Release (MVP)

### Added
- OPC UA Binary types and Hello/Ack transport codec.
- `OpcUaSession` abstraction.
- OPC UA adapter implementing the mcp_io 4-Primitive Contract.
