/// `Read` service request / response codecs (OPC UA Part 4 §5.10.2).
library;

import '../encoding/binary_reader.dart';
import '../encoding/binary_writer.dart';
import '../encoding/built_in_types.dart';
import '../encoding/data_value_codec.dart';
import '../encoding/node_id_codec.dart';
import 'request_header.dart';

/// `TimestampsToReturn` enum — Part 4 §7.32.
enum OpcUaTimestampsToReturn {
  source(0),
  server(1),
  both(2),
  neither(3);

  const OpcUaTimestampsToReturn(this.id);
  final int id;

  static OpcUaTimestampsToReturn fromId(int id) {
    if (id < 0 || id > 3) {
      throw ArgumentError.value(id, 'id', 'invalid TimestampsToReturn');
    }
    return OpcUaTimestampsToReturn.values[id];
  }
}

/// Single node-attribute pair in a Read request (Part 4 §7.24).
class OpcUaReadValueId {
  final OpcUaNodeIdValue nodeId;

  /// One of [OpcUaAttribute] (numeric).
  final int attributeId;

  /// IndexRange — empty string means "the whole array".
  final String indexRange;

  /// QualifiedName "Default Binary"/"Default XML" — empty by default.
  final OpcUaQualifiedName dataEncoding;

  const OpcUaReadValueId({
    required this.nodeId,
    required this.attributeId,
    this.indexRange = '',
    this.dataEncoding = const OpcUaQualifiedName(namespaceIndex: 0, name: ''),
  });

  void encode(BinaryWriter w) {
    NodeIdCodec.encode(w, nodeId);
    w.writeUint32(attributeId);
    w.writeStringOrNull(indexRange);
    w.writeUint16(dataEncoding.namespaceIndex);
    w.writeStringOrNull(dataEncoding.name);
  }

  factory OpcUaReadValueId.decode(BinaryReader r) {
    final nodeId = NodeIdCodec.decode(r);
    final attr = r.readUint32();
    final range = r.readStringOrNull() ?? '';
    final qnNs = r.readUint16();
    final qnName = r.readStringOrNull() ?? '';
    return OpcUaReadValueId(
      nodeId: nodeId,
      attributeId: attr,
      indexRange: range,
      dataEncoding: OpcUaQualifiedName(namespaceIndex: qnNs, name: qnName),
    );
  }
}

class OpcUaReadRequest {
  final OpcUaRequestHeader header;
  final double maxAge;
  final OpcUaTimestampsToReturn timestampsToReturn;
  final List<OpcUaReadValueId> nodesToRead;

  const OpcUaReadRequest({
    required this.header,
    this.maxAge = 0,
    this.timestampsToReturn = OpcUaTimestampsToReturn.both,
    required this.nodesToRead,
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    w.writeFloat64(maxAge);
    w.writeUint32(timestampsToReturn.id);
    w.writeInt32(nodesToRead.length);
    for (final n in nodesToRead) {
      n.encode(w);
    }
  }

  factory OpcUaReadRequest.decode(BinaryReader r) {
    final header = OpcUaRequestHeader.decode(r);
    final maxAge = r.readFloat64();
    final ts = OpcUaTimestampsToReturn.fromId(r.readUint32());
    final n = r.readInt32();
    final list = <OpcUaReadValueId>[
      for (var i = 0; i < n; i++) OpcUaReadValueId.decode(r),
    ];
    return OpcUaReadRequest(
      header: header,
      maxAge: maxAge,
      timestampsToReturn: ts,
      nodesToRead: list,
    );
  }
}

class OpcUaReadResponse {
  final OpcUaResponseHeader header;
  final List<OpcUaDataValue> results;

  /// `0` mask byte per row when no diagnostics are returned. The codec
  /// preserves an empty list ↔ a `-1` length on the wire.
  final List<int> diagnosticInfoMasks;

  const OpcUaReadResponse({
    required this.header,
    required this.results,
    this.diagnosticInfoMasks = const [],
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    w.writeInt32(results.length);
    for (final dv in results) {
      DataValueCodec.encode(w, dv);
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

  factory OpcUaReadResponse.decode(BinaryReader r) {
    final header = OpcUaResponseHeader.decode(r);
    final n = r.readInt32();
    final values = <OpcUaDataValue>[
      for (var i = 0; i < n; i++) DataValueCodec.decode(r),
    ];
    final dn = r.readInt32();
    final diagnostics = <int>[];
    if (dn > 0) {
      for (var i = 0; i < dn; i++) {
        final m = r.readUint8();
        if (m != 0) {
          throw StateError(
              'OpcUaReadResponse: non-empty DiagnosticInfo not supported');
        }
        diagnostics.add(m);
      }
    }
    return OpcUaReadResponse(
      header: header,
      results: values,
      diagnosticInfoMasks: diagnostics,
    );
  }
}
