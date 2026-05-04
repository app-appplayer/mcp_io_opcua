/// Production `OpcUaByteTransport` over a `dart:io` `Socket`.
///
/// Imports `dart:io`, so this file is **not** exported from the main
/// `mcp_io_opcua` library. Use it via `package:mcp_io_opcua/io.dart`
/// (the io-only entry point) on VM / Flutter desktop / Flutter mobile
/// targets. Web consumers must not import it.
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'byte_transport.dart';

/// `OpcUaByteTransport` over a TCP socket.
///
/// Construction is lazy — call [open] to dial the socket. Once open,
/// outgoing bytes are written and flushed; incoming bytes are
/// re-published on [incoming] as the OS read buffer hands them over.
/// `done`/error from the underlying socket closes the [incoming]
/// stream and marks the transport closed.
class TcpOpcUaByteTransport implements OpcUaByteTransport {
  /// Hostname or IPv4/IPv6 literal of the target opc.tcp endpoint.
  final String host;

  /// TCP port.
  final int port;

  /// Optional dial timeout. `null` falls back to the OS default.
  final Duration? connectTimeout;

  Socket? _socket;
  // ignore: close_sinks
  final StreamController<Uint8List> _rxCtrl =
      StreamController<Uint8List>.broadcast();
  StreamSubscription<Uint8List>? _rxSub;
  bool _opened = false;
  bool _closed = false;

  TcpOpcUaByteTransport({
    required this.host,
    required this.port,
    this.connectTimeout,
  });

  /// Build a transport from an `opc.tcp://host[:port][/path]` URI.
  /// `port` defaults to 4840 when not specified — the IANA-registered
  /// OPC UA TCP Binary port.
  factory TcpOpcUaByteTransport.fromEndpoint(
    Uri endpoint, {
    Duration? connectTimeout,
  }) {
    if (endpoint.scheme != 'opc.tcp') {
      throw ArgumentError.value(
        endpoint, 'endpoint',
        'TcpOpcUaByteTransport expects an opc.tcp:// endpoint',
      );
    }
    final host = endpoint.host;
    final port = endpoint.hasPort ? endpoint.port : 4840;
    return TcpOpcUaByteTransport(
      host: host, port: port, connectTimeout: connectTimeout,
    );
  }

  bool get isOpen => _opened && !_closed;

  @override
  Future<void> open() async {
    if (_closed) {
      throw StateError('TcpOpcUaByteTransport already closed');
    }
    if (_opened) return;
    final fut = Socket.connect(host, port);
    final socket = await (connectTimeout == null
        ? fut
        : fut.timeout(connectTimeout!));
    socket.setOption(SocketOption.tcpNoDelay, true);
    _socket = socket;
    _rxSub = socket.listen(
      (chunk) {
        if (!_rxCtrl.isClosed) _rxCtrl.add(chunk);
      },
      onError: (Object e, StackTrace st) {
        if (!_rxCtrl.isClosed) _rxCtrl.addError(e, st);
      },
      onDone: () {
        // Remote closed — surface a transparent close to the consumer.
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
    final s = _socket;
    if (s == null || _closed) {
      throw StateError('TcpOpcUaByteTransport not open');
    }
    s.add(bytes);
    await s.flush();
  }

  @override
  Stream<Uint8List> get incoming => _rxCtrl.stream;

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _rxSub?.cancel();
    _rxSub = null;
    final s = _socket;
    _socket = null;
    if (s != null) {
      try {
        await s.close();
      } on Object {
        // Best-effort. The socket may already be torn down on the
        // remote side.
      }
      s.destroy();
    }
    if (!_rxCtrl.isClosed) {
      await _rxCtrl.close();
    }
  }
}
