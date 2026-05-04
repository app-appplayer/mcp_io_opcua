/// `Call` service request / response codecs (OPC UA Part 4 §5.11.2).
library;

import '../encoding/binary_reader.dart';
import '../encoding/binary_writer.dart';
import '../encoding/node_id_codec.dart';
import '../encoding/variant_codec.dart';
import 'request_header.dart';

class OpcUaCallMethodRequestRow {
  final OpcUaNodeIdValue objectId;
  final OpcUaNodeIdValue methodId;
  final List<OpcUaVariantValue> inputArguments;

  const OpcUaCallMethodRequestRow({
    required this.objectId,
    required this.methodId,
    this.inputArguments = const [],
  });

  void encode(BinaryWriter w) {
    NodeIdCodec.encode(w, objectId);
    NodeIdCodec.encode(w, methodId);
    w.writeInt32(inputArguments.length);
    for (final a in inputArguments) {
      VariantCodec.encode(w, a);
    }
  }

  factory OpcUaCallMethodRequestRow.decode(BinaryReader r) {
    final obj = NodeIdCodec.decode(r);
    final mth = NodeIdCodec.decode(r);
    final n = r.readInt32();
    final args = <OpcUaVariantValue>[
      for (var i = 0; i < n; i++) VariantCodec.decode(r),
    ];
    return OpcUaCallMethodRequestRow(
      objectId: obj, methodId: mth, inputArguments: args,
    );
  }
}

class OpcUaCallMethodResultRow {
  final int statusCode;
  final List<int> inputArgumentResults;
  final List<int> inputArgumentDiagnosticInfoMasks;
  final List<OpcUaVariantValue> outputArguments;

  const OpcUaCallMethodResultRow({
    this.statusCode = 0,
    this.inputArgumentResults = const [],
    this.inputArgumentDiagnosticInfoMasks = const [],
    this.outputArguments = const [],
  });

  void encode(BinaryWriter w) {
    w.writeUint32(statusCode);
    if (inputArgumentResults.isEmpty) {
      w.writeInt32(-1);
    } else {
      w.writeInt32(inputArgumentResults.length);
      for (final c in inputArgumentResults) {
        w.writeUint32(c);
      }
    }
    if (inputArgumentDiagnosticInfoMasks.isEmpty) {
      w.writeInt32(-1);
    } else {
      w.writeInt32(inputArgumentDiagnosticInfoMasks.length);
      for (final m in inputArgumentDiagnosticInfoMasks) {
        w.writeUint8(m);
      }
    }
    if (outputArguments.isEmpty) {
      w.writeInt32(-1);
    } else {
      w.writeInt32(outputArguments.length);
      for (final v in outputArguments) {
        VariantCodec.encode(w, v);
      }
    }
  }

  factory OpcUaCallMethodResultRow.decode(BinaryReader r) {
    final status = r.readUint32();
    final ic = r.readInt32();
    final inputResults = <int>[];
    if (ic > 0) {
      for (var i = 0; i < ic; i++) {
        inputResults.add(r.readUint32());
      }
    }
    final dc = r.readInt32();
    final diag = <int>[];
    if (dc > 0) {
      for (var i = 0; i < dc; i++) {
        final m = r.readUint8();
        if (m != 0) {
          throw StateError(
            'OpcUaCallMethodResultRow: non-empty DiagnosticInfo not supported',
          );
        }
        diag.add(m);
      }
    }
    final oc = r.readInt32();
    final outputs = <OpcUaVariantValue>[];
    if (oc > 0) {
      for (var i = 0; i < oc; i++) {
        outputs.add(VariantCodec.decode(r));
      }
    }
    return OpcUaCallMethodResultRow(
      statusCode: status,
      inputArgumentResults: inputResults,
      inputArgumentDiagnosticInfoMasks: diag,
      outputArguments: outputs,
    );
  }
}

class OpcUaCallRequest {
  final OpcUaRequestHeader header;
  final List<OpcUaCallMethodRequestRow> methodsToCall;

  const OpcUaCallRequest({
    required this.header,
    required this.methodsToCall,
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    w.writeInt32(methodsToCall.length);
    for (final m in methodsToCall) {
      m.encode(w);
    }
  }

  factory OpcUaCallRequest.decode(BinaryReader r) {
    final header = OpcUaRequestHeader.decode(r);
    final n = r.readInt32();
    final list = <OpcUaCallMethodRequestRow>[
      for (var i = 0; i < n; i++) OpcUaCallMethodRequestRow.decode(r),
    ];
    return OpcUaCallRequest(header: header, methodsToCall: list);
  }
}

class OpcUaCallResponse {
  final OpcUaResponseHeader header;
  final List<OpcUaCallMethodResultRow> results;
  final List<int> diagnosticInfoMasks;

  const OpcUaCallResponse({
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

  factory OpcUaCallResponse.decode(BinaryReader r) {
    final header = OpcUaResponseHeader.decode(r);
    final n = r.readInt32();
    final rows = <OpcUaCallMethodResultRow>[
      for (var i = 0; i < n; i++) OpcUaCallMethodResultRow.decode(r),
    ];
    final dn = r.readInt32();
    final diag = <int>[];
    if (dn > 0) {
      for (var i = 0; i < dn; i++) {
        final m = r.readUint8();
        if (m != 0) {
          throw StateError(
              'OpcUaCallResponse: non-empty DiagnosticInfo not supported');
        }
        diag.add(m);
      }
    }
    return OpcUaCallResponse(
      header: header, results: rows, diagnosticInfoMasks: diag,
    );
  }
}
