## [0.2.1] - 2026-05-23 - mcp_bundle 0.4.0 cascade

### Changed (cascade)
- `mcp_bundle` caret bumped from `^0.3.0` to `^0.4.0`.
- `mcp_io` caret bumped from `^0.2.0` to `^0.2.1`.

mcp_io_opcua does not touch `UiSection.pages` directly — caret-only cascade. Consumers should bump to `^0.2.1`.

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
