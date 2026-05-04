/// `Write` service request / response codecs (OPC UA Part 4 §5.10.4).
library;

import '../encoding/binary_reader.dart';
import '../encoding/binary_writer.dart';
import '../encoding/data_value_codec.dart';
import '../encoding/node_id_codec.dart';
import 'request_header.dart';

/// Single (NodeId, AttributeId, value) tuple in a Write request.
class OpcUaWriteValue {
  final OpcUaNodeIdValue nodeId;
  final int attributeId;

  /// Empty string means "the whole array".
  final String indexRange;

  final OpcUaDataValue value;

  const OpcUaWriteValue({
    required this.nodeId,
    required this.attributeId,
    required this.value,
    this.indexRange = '',
  });

  void encode(BinaryWriter w) {
    NodeIdCodec.encode(w, nodeId);
    w.writeUint32(attributeId);
    w.writeStringOrNull(indexRange);
    DataValueCodec.encode(w, value);
  }

  factory OpcUaWriteValue.decode(BinaryReader r) {
    final nodeId = NodeIdCodec.decode(r);
    final attr = r.readUint32();
    final range = r.readStringOrNull() ?? '';
    final dv = DataValueCodec.decode(r);
    return OpcUaWriteValue(
      nodeId: nodeId,
      attributeId: attr,
      indexRange: range,
      value: dv,
    );
  }
}

class OpcUaWriteRequest {
  final OpcUaRequestHeader header;
  final List<OpcUaWriteValue> nodesToWrite;

  const OpcUaWriteRequest({
    required this.header,
    required this.nodesToWrite,
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    w.writeInt32(nodesToWrite.length);
    for (final n in nodesToWrite) {
      n.encode(w);
    }
  }

  factory OpcUaWriteRequest.decode(BinaryReader r) {
    final header = OpcUaRequestHeader.decode(r);
    final n = r.readInt32();
    final list = <OpcUaWriteValue>[
      for (var i = 0; i < n; i++) OpcUaWriteValue.decode(r),
    ];
    return OpcUaWriteRequest(header: header, nodesToWrite: list);
  }
}

/// `WriteResponse` carries one StatusCode per row in [OpcUaWriteRequest.nodesToWrite].
class OpcUaWriteResponse {
  final OpcUaResponseHeader header;
  final List<int> results;
  final List<int> diagnosticInfoMasks;

  const OpcUaWriteResponse({
    required this.header,
    required this.results,
    this.diagnosticInfoMasks = const [],
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    w.writeInt32(results.length);
    for (final code in results) {
      w.writeUint32(code);
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

  factory OpcUaWriteResponse.decode(BinaryReader r) {
    final header = OpcUaResponseHeader.decode(r);
    final n = r.readInt32();
    final results = <int>[for (var i = 0; i < n; i++) r.readUint32()];
    final dn = r.readInt32();
    final diagnostics = <int>[];
    if (dn > 0) {
      for (var i = 0; i < dn; i++) {
        final m = r.readUint8();
        if (m != 0) {
          throw StateError(
              'OpcUaWriteResponse: non-empty DiagnosticInfo not supported');
        }
        diagnostics.add(m);
      }
    }
    return OpcUaWriteResponse(
      header: header, results: results, diagnosticInfoMasks: diagnostics,
    );
  }
}
