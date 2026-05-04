/// Request / Response headers shared by every OPC UA service.
///
/// Spec: Part 4 §7.30 (RequestHeader) and §7.31 (ResponseHeader).
library;

import '../encoding/binary_reader.dart';
import '../encoding/binary_writer.dart';
import '../encoding/extension_object_codec.dart';
import '../encoding/node_id_codec.dart';

/// Common preamble for every service request.
///
/// In the None-security context the AuthenticationToken is the null NodeId
/// until a session has been activated, after which it carries the session
/// identifier returned by ActivateSession.
class OpcUaRequestHeader {
  /// Session-level token returned by `CreateSession` / `ActivateSession`.
  /// `OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 0)` for unsessioned
  /// requests (e.g. discovery).
  final OpcUaNodeIdValue authenticationToken;

  /// 100-ns ticks since 1601-01-01 UTC. Encoded as Int64 LE.
  final DateTime timestamp;

  /// Caller-chosen monotonic id. Echoed in [OpcUaResponseHeader.requestHandle].
  final int requestHandle;

  /// Bitmask requesting diagnostic detail in the response (Part 4 §7.8).
  final int returnDiagnostics;

  /// Free-form string written to the server's audit log. May be empty.
  final String auditEntryId;

  /// Caller-suggested deadline in ms. Servers MAY override.
  final int timeoutHint;

  /// Always `null` body in this implementation.
  final OpcUaExtensionObject additionalHeader;

  OpcUaRequestHeader({
    required this.authenticationToken,
    required this.timestamp,
    required this.requestHandle,
    this.returnDiagnostics = 0,
    this.auditEntryId = '',
    this.timeoutHint = 60000,
    OpcUaExtensionObject? additionalHeader,
  }) : additionalHeader = additionalHeader ?? _nullExtensionObject;

  void encode(BinaryWriter w) {
    NodeIdCodec.encode(w, authenticationToken);
    w.writeInt64(_dateTimeToTicks(timestamp));
    w.writeUint32(requestHandle);
    w.writeUint32(returnDiagnostics);
    w.writeStringOrNull(auditEntryId);
    w.writeUint32(timeoutHint);
    ExtensionObjectCodec.encode(w, additionalHeader);
  }

  factory OpcUaRequestHeader.decode(BinaryReader r) {
    final token = NodeIdCodec.decode(r);
    final ticks = r.readInt64();
    final handle = r.readUint32();
    final diagnostics = r.readUint32();
    final audit = r.readStringOrNull() ?? '';
    final timeout = r.readUint32();
    final addl = ExtensionObjectCodec.decode(r);
    return OpcUaRequestHeader(
      authenticationToken: token,
      timestamp: _ticksToDateTime(ticks),
      requestHandle: handle,
      returnDiagnostics: diagnostics,
      auditEntryId: audit,
      timeoutHint: timeout,
      additionalHeader: addl,
    );
  }
}

/// Common preamble for every service response.
class OpcUaResponseHeader {
  final DateTime timestamp;
  final int requestHandle;

  /// Service-level status code (separate from per-row Results in Read/Write).
  final int serviceResult;

  /// `0` = no diagnostics (only mask byte written). Non-zero values
  /// require a full DiagnosticInfo decoder, which is beyond the scope
  /// of this codec.
  final int serviceDiagnosticsMask;

  /// String table referenced by DiagnosticInfo. Often empty.
  final List<String> stringTable;

  final OpcUaExtensionObject additionalHeader;

  OpcUaResponseHeader({
    required this.timestamp,
    required this.requestHandle,
    this.serviceResult = 0,
    this.serviceDiagnosticsMask = 0,
    this.stringTable = const [],
    OpcUaExtensionObject? additionalHeader,
  }) : additionalHeader = additionalHeader ?? _nullExtensionObject;

  bool get isGood => serviceResult == 0;

  void encode(BinaryWriter w) {
    w.writeInt64(_dateTimeToTicks(timestamp));
    w.writeUint32(requestHandle);
    w.writeUint32(serviceResult);
    w.writeUint8(serviceDiagnosticsMask);
    w.writeInt32(stringTable.length);
    for (final s in stringTable) {
      w.writeStringOrNull(s);
    }
    ExtensionObjectCodec.encode(w, additionalHeader);
  }

  factory OpcUaResponseHeader.decode(BinaryReader r) {
    final ticks = r.readInt64();
    final handle = r.readUint32();
    final result = r.readUint32();
    final diagnosticsMask = r.readUint8();
    if (diagnosticsMask != 0) {
      throw StateError(
          'OpcUaResponseHeader: non-empty DiagnosticInfo not supported '
          '(mask=0x${diagnosticsMask.toRadixString(16)})');
    }
    final tableLen = r.readInt32();
    final table = <String>[];
    if (tableLen > 0) {
      for (var i = 0; i < tableLen; i++) {
        table.add(r.readStringOrNull() ?? '');
      }
    }
    final addl = ExtensionObjectCodec.decode(r);
    return OpcUaResponseHeader(
      timestamp: _ticksToDateTime(ticks),
      requestHandle: handle,
      serviceResult: result,
      serviceDiagnosticsMask: diagnosticsMask,
      stringTable: table,
      additionalHeader: addl,
    );
  }
}

/// `OpcUaExtensionObject` whose typeId is the null NodeId — the canonical
/// "no additional header" marker.
final OpcUaExtensionObject _nullExtensionObject = OpcUaExtensionObject(
  typeId: const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 0),
  encoding: ExtensionObjectEncoding.noBody,
);

const int _epochOffsetMicros = -11644473600000000;

int _dateTimeToTicks(DateTime dt) =>
    (dt.toUtc().microsecondsSinceEpoch - _epochOffsetMicros) * 10;

DateTime _ticksToDateTime(int ticks) =>
    DateTime.fromMicrosecondsSinceEpoch(
        (ticks ~/ 10) + _epochOffsetMicros, isUtc: true);
