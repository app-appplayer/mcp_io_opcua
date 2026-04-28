/// OPC UA session abstraction — hides the full binary service set behind a
/// small interface the adapter can call.
///
/// A production implementation layers `OpenSecureChannel` + `CreateSession` +
/// `ActivateSession` + `Read`/`Write`/`CloseSession` over a TCP socket (after
/// the Hello/Acknowledge handshake handled by `opcua_hello.dart`). This MVP
/// ships an in-memory implementation for tests and simulation.
library;

import 'opcua_types.dart';

abstract class OpcUaSession {
  /// Open and activate the session. Idempotent.
  Future<void> open();

  /// Read a single NodeId's current value. Returns a [OpcUaVariant.nullValue]
  /// when the node is not known; throws on protocol error.
  Future<OpcUaVariant> read(OpcUaNodeId nodeId);

  /// Write a single NodeId's value. Throws on failure.
  Future<void> write(OpcUaNodeId nodeId, OpcUaVariant value);

  /// Close session + secure channel.
  Future<void> close();
}

/// In-memory simulation of an OPC UA server. Tests seed node values via
/// [seed]; reads/writes go against that in-memory map.
class InMemoryOpcUaSession implements OpcUaSession {
  final Map<OpcUaNodeId, OpcUaVariant> _values = {};
  bool isOpen = false;
  bool isClosed = false;
  int readCount = 0;
  int writeCount = 0;

  @override
  Future<void> open() async {
    if (isClosed) throw const OpcUaProtocolError('session already closed');
    isOpen = true;
  }

  @override
  Future<OpcUaVariant> read(OpcUaNodeId nodeId) async {
    if (!isOpen) {
      throw const OpcUaProtocolError('session not open');
    }
    readCount++;
    return _values[nodeId] ?? const OpcUaVariant.nullValue();
  }

  @override
  Future<void> write(OpcUaNodeId nodeId, OpcUaVariant value) async {
    if (!isOpen) {
      throw const OpcUaProtocolError('session not open');
    }
    writeCount++;
    _values[nodeId] = value;
  }

  @override
  Future<void> close() async {
    isClosed = true;
    isOpen = false;
  }

  /// Test helper — seed an initial value for [nodeId].
  void seed(OpcUaNodeId nodeId, OpcUaVariant value) {
    _values[nodeId] = value;
  }

  /// Test helper — return a snapshot of the current node values.
  Map<OpcUaNodeId, OpcUaVariant> snapshot() =>
      Map.unmodifiable(_values);
}
