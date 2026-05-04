/// `OpcUaByteTransport` over an OPC UA / WebSocket binary tunnel
/// (Part 6 §7.4 — WebSocket Mappings).
///
/// Wire profile: `opc.wss://host[:port][/path]` for TLS or
/// `opc.ws://` for plaintext. Each WebSocket binary frame carries
/// exactly one OPC UA conversation message (HEL/ACK/OPN/CLO/MSG)
/// — the protocol session reuses the same frame pump as the TCP
/// transport.
///
/// Subprotocol negotiation: by default we request `opcua+cp` (the
/// Conversation Protocol — wire-identical to TCP framing), which is
/// the dialect the OPC Foundation reference servers speak. Pass a
/// custom value via [subprotocols] if the target server expects a
/// different name.
///
/// This module imports `dart:io`, so it lives behind the io-only
/// entry point `package:mcp_io_opcua/io.dart` to keep the main
/// library web-safe (web Flutter targets get the abstract `OpcUaByteTransport`
/// + paired in-memory implementation only).
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'byte_transport.dart';

class WebSocketOpcUaByteTransport implements OpcUaByteTransport {
  /// Endpoint URI — accepts `opc.ws` / `opc.wss` (translated to
  /// `ws` / `wss` for the underlying dart:io call) as well as raw
  /// `ws://` / `wss://`.
  final Uri endpoint;

  /// WebSocket subprotocols offered to the server. Default
  /// `['opcua+cp']` (OPC UA Conversation Protocol over WebSocket).
  final List<String> subprotocols;

  /// Optional dial timeout. `null` falls back to the OS default.
  final Duration? connectTimeout;

  WebSocket? _ws;
  // ignore: close_sinks
  final StreamController<Uint8List> _rxCtrl =
      StreamController<Uint8List>.broadcast();
  StreamSubscription<dynamic>? _rxSub;
  bool _opened = false;
  bool _closed = false;

  WebSocketOpcUaByteTransport({
    required this.endpoint,
    this.subprotocols = const ['opcua+cp'],
    this.connectTimeout,
  });

  /// `true` while the underlying socket is open and not yet closed.
  bool get isOpen => _opened && !_closed;

  /// Subprotocol the server actually selected during the handshake
  /// (`null` when the socket has not been opened yet).
  String? get selectedSubprotocol => _ws?.protocol;

  @override
  Future<void> open() async {
    if (_closed) {
      throw StateError('WebSocketOpcUaByteTransport already closed');
    }
    if (_opened) return;
    final wsUri = _toWsUri(endpoint);
    final fut =
        WebSocket.connect(wsUri.toString(), protocols: subprotocols);
    final ws = await (connectTimeout == null
        ? fut
        : fut.timeout(connectTimeout!));
    _ws = ws;
    _rxSub = ws.listen(
      (event) {
        if (_rxCtrl.isClosed) return;
        if (event is List<int>) {
          _rxCtrl.add(
            event is Uint8List ? event : Uint8List.fromList(event),
          );
        }
        // Text frames are not part of the OPC UA Conversation
        // Protocol; ignore.
      },
      onError: (Object e, StackTrace st) {
        if (!_rxCtrl.isClosed) _rxCtrl.addError(e, st);
      },
      onDone: () {
        if (!_closed) {
          _closed = true;
          if (!_rxCtrl.isClosed) _rxCtrl.close();
        }
      },
      cancelOnError: false,
    );
    _opened = true;
  }

  @override
  Future<void> send(List<int> bytes) async {
    final ws = _ws;
    if (ws == null || _closed) {
      throw StateError('WebSocketOpcUaByteTransport not open');
    }
    // `add` on a binary-typed payload triggers a single binary
    // WebSocket frame.
    ws.add(bytes);
  }

  @override
  Stream<Uint8List> get incoming => _rxCtrl.stream;

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _rxSub?.cancel();
    _rxSub = null;
    final ws = _ws;
    _ws = null;
    if (ws != null) {
      try {
        await ws.close();
      } on Object {
        // Best-effort.
      }
    }
    if (!_rxCtrl.isClosed) {
      await _rxCtrl.close();
    }
  }

  /// Translate `opc.ws[s]` into the `ws[s]` scheme dart:io
  /// understands. Pass-through for plain `ws[s]` URIs.
  static Uri _toWsUri(Uri endpoint) {
    if (endpoint.scheme == 'opc.ws' || endpoint.scheme == 'ws') {
      return endpoint.replace(scheme: 'ws');
    }
    if (endpoint.scheme == 'opc.wss' || endpoint.scheme == 'wss') {
      return endpoint.replace(scheme: 'wss');
    }
    throw ArgumentError.value(
      endpoint, 'endpoint',
      'WebSocketOpcUaByteTransport expects opc.ws / opc.wss / ws / wss '
      '(got ${endpoint.scheme})',
    );
  }
}
