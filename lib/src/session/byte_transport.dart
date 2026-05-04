/// Lower-level byte transport for the OPC UA Binary protocol.
///
/// The OPC UA Binary stack ships its messages over **opc.tcp** (a stream
/// transport). This module abstracts the byte-pump so the higher-level
/// session orchestrator stays portable:
///
///   - production deployments inject a `TcpOpcUaByteTransport` over
///     `dart:io Socket` (ships separately to keep the core library
///     hermetic).
///   - tests use [InMemoryOpcUaByteTransport.paired] to wire two
///     in-process endpoints together.
///
/// Frame parsing lives in `frame_pump.dart`; this layer only moves
/// arbitrary-size byte chunks.
library;

import 'dart:async';
import 'dart:typed_data';

abstract class OpcUaByteTransport {
  /// Opens the underlying connection. Idempotent.
  Future<void> open();

  /// Send the supplied bytes verbatim.
  Future<void> send(List<int> bytes);

  /// Stream of incoming byte chunks. Each event is whatever the OS read
  /// buffer returned — frames are *not* aligned to chunks; the consumer
  /// must reassemble.
  Stream<Uint8List> get incoming;

  /// Closes the connection. Idempotent.
  Future<void> close();
}

/// In-memory paired transport for tests.
///
/// Construct two with [InMemoryOpcUaByteTransport.paired] then
/// [pairWith] them together — `send` on one delivers to the other's
/// `incoming` stream and vice versa.
///
/// `inject` lets a test simulate server-originated bytes without
/// wiring a peer.
class InMemoryOpcUaByteTransport implements OpcUaByteTransport {
  final StreamController<Uint8List> _rxCtrl =
      StreamController<Uint8List>.broadcast();

  /// Bytes the local side has sent, in order.
  final List<Uint8List> sent = [];

  InMemoryOpcUaByteTransport? _peer;
  bool isOpen = false;
  bool isClosed = false;

  InMemoryOpcUaByteTransport();

  /// Bi-directionally connect two in-memory transports.
  void pairWith(InMemoryOpcUaByteTransport other) {
    _peer = other;
    other._peer = this;
  }

  @override
  Future<void> open() async {
    if (isClosed) {
      throw StateError('InMemoryOpcUaByteTransport already closed');
    }
    isOpen = true;
  }

  @override
  Future<void> send(List<int> bytes) async {
    if (isClosed) throw StateError('byte transport closed');
    final chunk = Uint8List.fromList(bytes);
    sent.add(chunk);
    final peer = _peer;
    if (peer != null && !peer.isClosed) {
      peer._rxCtrl.add(chunk);
    }
  }

  @override
  Stream<Uint8List> get incoming => _rxCtrl.stream;

  @override
  Future<void> close() async {
    if (isClosed) return;
    isClosed = true;
    if (!_rxCtrl.isClosed) {
      await _rxCtrl.close();
    }
  }

  /// Test helper — push bytes onto this side's `incoming` stream as if a
  /// peer had sent them. Useful for unit-testing parsers without a peer.
  void inject(List<int> bytes) {
    if (_rxCtrl.isClosed) return;
    _rxCtrl.add(Uint8List.fromList(bytes));
  }
}
