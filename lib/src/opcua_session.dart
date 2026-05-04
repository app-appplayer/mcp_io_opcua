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

  /// Browse references from [from]. Default unsupported.
  Future<List<OpcUaReferenceDescription>> browse(
    OpcUaNodeId from, {
    int? maxResults,
  }) =>
      throw const OpcUaProtocolError('browse not implemented for this session');

  /// Invoke an OPC UA Method. Default unsupported.
  Future<OpcUaCallResult> callMethod(
    OpcUaNodeId object,
    OpcUaNodeId method,
    List<OpcUaVariant> inputs,
  ) =>
      throw const OpcUaProtocolError('callMethod not implemented for this session');

  /// HistoryRead for a node within the supplied time window.
  /// Default unsupported.
  Future<List<OpcUaHistoryDataPoint>> historyRead(
    OpcUaNodeId nodeId, {
    required DateTime from,
    required DateTime to,
    int? maxValues,
  }) =>
      throw const OpcUaProtocolError('historyRead not implemented for this session');

  /// Close session + secure channel.
  Future<void> close();
}

/// In-memory simulation of an OPC UA server. Tests seed node values via
/// [seed]; reads/writes go against that in-memory map.
class InMemoryOpcUaSession implements OpcUaSession {
  final Map<OpcUaNodeId, OpcUaVariant> _values = {};
  final Map<OpcUaNodeId, List<OpcUaReferenceDescription>> _references = {};
  final Map<OpcUaNodeId, List<OpcUaHistoryDataPoint>> _history = {};
  final Map<String, OpcUaCallResult Function(List<OpcUaVariant>)> _methods = {};

  bool isOpen = false;
  bool isClosed = false;
  int readCount = 0;
  int writeCount = 0;
  int browseCount = 0;
  int callCount = 0;
  int historyCount = 0;

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
  Future<List<OpcUaReferenceDescription>> browse(
    OpcUaNodeId from, {
    int? maxResults,
  }) async {
    if (!isOpen) throw const OpcUaProtocolError('session not open');
    browseCount++;
    final all = _references[from] ?? const [];
    if (maxResults == null || maxResults >= all.length) return all;
    return all.sublist(0, maxResults);
  }

  @override
  Future<OpcUaCallResult> callMethod(
    OpcUaNodeId object,
    OpcUaNodeId method,
    List<OpcUaVariant> inputs,
  ) async {
    if (!isOpen) throw const OpcUaProtocolError('session not open');
    callCount++;
    final key = '${object.toStandardString()}::${method.toStandardString()}';
    final fn = _methods[key];
    if (fn == null) {
      return const OpcUaCallResult(statusCode: 0x803F0000); // BadMethodInvalid
    }
    return fn(inputs);
  }

  @override
  Future<List<OpcUaHistoryDataPoint>> historyRead(
    OpcUaNodeId nodeId, {
    required DateTime from,
    required DateTime to,
    int? maxValues,
  }) async {
    if (!isOpen) throw const OpcUaProtocolError('session not open');
    historyCount++;
    final all = _history[nodeId] ?? const [];
    final filtered = [
      for (final p in all)
        if (!p.sourceTimestamp.isBefore(from) &&
            !p.sourceTimestamp.isAfter(to))
          p,
    ];
    if (maxValues == null || maxValues >= filtered.length) return filtered;
    return filtered.sublist(0, maxValues);
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

  /// Test helper — register references from [from] to be returned by browse.
  void seedReferences(
    OpcUaNodeId from,
    List<OpcUaReferenceDescription> refs,
  ) {
    _references[from] = List.unmodifiable(refs);
  }

  /// Test helper — register a method handler.
  void registerMethod(
    OpcUaNodeId object,
    OpcUaNodeId method,
    OpcUaCallResult Function(List<OpcUaVariant> inputs) handler,
  ) {
    _methods['${object.toStandardString()}::${method.toStandardString()}'] =
        handler;
  }

  /// Test helper — append a historic data point for [nodeId].
  void seedHistory(OpcUaNodeId nodeId, OpcUaHistoryDataPoint point) {
    (_history[nodeId] ??= []).add(point);
  }

  /// Test helper — return a snapshot of the current node values.
  Map<OpcUaNodeId, OpcUaVariant> snapshot() =>
      Map.unmodifiable(_values);
}
