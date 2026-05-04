/// `HistoryRead` service request / response codecs (OPC UA Part 4 §5.10.3).
///
/// Both `historyReadDetails` (request) and `historyData` (response per row)
/// are carried as raw `OpcUaExtensionObject` — application code is expected
/// to inject / parse the concrete struct (e.g. `ReadRawModifiedDetails`,
/// `ReadAtTimeDetails`, `HistoryData`, `HistoryEvent`) on top.
library;

import '../encoding/binary_reader.dart';
import '../encoding/binary_writer.dart';
import '../encoding/built_in_types.dart';
import '../encoding/extension_object_codec.dart';
import '../encoding/node_id_codec.dart';
import 'read_service.dart';
import 'request_header.dart';

class OpcUaHistoryReadValueId {
  final OpcUaNodeIdValue nodeId;
  final String indexRange;
  final OpcUaQualifiedName dataEncoding;
  final List<int>? continuationPoint;

  const OpcUaHistoryReadValueId({
    required this.nodeId,
    this.indexRange = '',
    this.dataEncoding =
        const OpcUaQualifiedName(namespaceIndex: 0, name: ''),
    this.continuationPoint,
  });

  void encode(BinaryWriter w) {
    NodeIdCodec.encode(w, nodeId);
    w.writeStringOrNull(indexRange);
    w.writeUint16(dataEncoding.namespaceIndex);
    w.writeStringOrNull(dataEncoding.name);
    w.writeByteStringOrNull(continuationPoint);
  }

  factory OpcUaHistoryReadValueId.decode(BinaryReader r) {
    final nodeId = NodeIdCodec.decode(r);
    final range = r.readStringOrNull() ?? '';
    final qnNs = r.readUint16();
    final qnName = r.readStringOrNull() ?? '';
    final cp = r.readByteStringOrNull();
    return OpcUaHistoryReadValueId(
      nodeId: nodeId,
      indexRange: range,
      dataEncoding: OpcUaQualifiedName(namespaceIndex: qnNs, name: qnName),
      continuationPoint: cp,
    );
  }
}

class OpcUaHistoryReadResultRow {
  final int statusCode;
  final List<int>? continuationPoint;
  final OpcUaExtensionObject historyData;

  OpcUaHistoryReadResultRow({
    this.statusCode = 0,
    this.continuationPoint,
    OpcUaExtensionObject? historyData,
  }) : historyData = historyData ?? _nullHistoryData;

  void encode(BinaryWriter w) {
    w.writeUint32(statusCode);
    w.writeByteStringOrNull(continuationPoint);
    ExtensionObjectCodec.encode(w, historyData);
  }

  factory OpcUaHistoryReadResultRow.decode(BinaryReader r) {
    final status = r.readUint32();
    final cp = r.readByteStringOrNull();
    final data = ExtensionObjectCodec.decode(r);
    return OpcUaHistoryReadResultRow(
      statusCode: status, continuationPoint: cp, historyData: data,
    );
  }

  static final _nullHistoryData = OpcUaExtensionObject(
    typeId: const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 0),
    encoding: ExtensionObjectEncoding.noBody,
  );
}

class OpcUaHistoryReadRequest {
  final OpcUaRequestHeader header;
  final OpcUaExtensionObject historyReadDetails;
  final OpcUaTimestampsToReturn timestampsToReturn;
  final bool releaseContinuationPoints;
  final List<OpcUaHistoryReadValueId> nodesToRead;

  OpcUaHistoryReadRequest({
    required this.header,
    OpcUaExtensionObject? historyReadDetails,
    this.timestampsToReturn = OpcUaTimestampsToReturn.both,
    this.releaseContinuationPoints = false,
    required this.nodesToRead,
  }) : historyReadDetails = historyReadDetails ?? _nullDetails;

  void encode(BinaryWriter w) {
    header.encode(w);
    ExtensionObjectCodec.encode(w, historyReadDetails);
    w.writeUint32(timestampsToReturn.id);
    w.writeUint8(releaseContinuationPoints ? 1 : 0);
    w.writeInt32(nodesToRead.length);
    for (final n in nodesToRead) {
      n.encode(w);
    }
  }

  factory OpcUaHistoryReadRequest.decode(BinaryReader r) {
    final header = OpcUaRequestHeader.decode(r);
    final details = ExtensionObjectCodec.decode(r);
    final ts = OpcUaTimestampsToReturn.fromId(r.readUint32());
    final release = r.readUint8() != 0;
    final n = r.readInt32();
    final list = <OpcUaHistoryReadValueId>[
      for (var i = 0; i < n; i++) OpcUaHistoryReadValueId.decode(r),
    ];
    return OpcUaHistoryReadRequest(
      header: header,
      historyReadDetails: details,
      timestampsToReturn: ts,
      releaseContinuationPoints: release,
      nodesToRead: list,
    );
  }

  static final _nullDetails = OpcUaExtensionObject(
    typeId: const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 0),
    encoding: ExtensionObjectEncoding.noBody,
  );
}

class OpcUaHistoryReadResponse {
  final OpcUaResponseHeader header;
  final List<OpcUaHistoryReadResultRow> results;
  final List<int> diagnosticInfoMasks;

  const OpcUaHistoryReadResponse({
    required this.header,
    required this.results,
    this.diagnosticInfoMasks = const [],
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    w.writeInt32(results.length);
    for (final r in results) {
      r.encode(w);
    }
    if (diagnosticInfoMasks.isEmpty) {
      w.writeInt32(-1);
    } else {
      w.writeInt32(diagnosticInfoMasks.length);
      for (final m in diagnosticInfoMasks) {
        w.writeUint8(m);
      }
    }
  }

  factory OpcUaHistoryReadResponse.decode(BinaryReader r) {
    final header = OpcUaResponseHeader.decode(r);
    final n = r.readInt32();
    final rows = <OpcUaHistoryReadResultRow>[
      for (var i = 0; i < n; i++) OpcUaHistoryReadResultRow.decode(r),
    ];
    final dn = r.readInt32();
    final diag = <int>[];
    if (dn > 0) {
      for (var i = 0; i < dn; i++) {
        final m = r.readUint8();
        if (m != 0) {
          throw StateError(
            'OpcUaHistoryReadResponse: non-empty DiagnosticInfo not supported',
          );
        }
        diag.add(m);
      }
    }
    return OpcUaHistoryReadResponse(
      header: header, results: rows, diagnosticInfoMasks: diag,
    );
  }
}
