/// `Browse` service request / response codecs (OPC UA Part 4 §5.8.2).
///
/// ExpandedNodeId fields (`nodeId`, `typeDefinition` in ReferenceDescription)
/// are encoded as plain NodeId — namespaceUri / serverIndex flags (mask
/// 0x80 / 0x40) are not emitted. Decoders that observe those flags must
/// reach for a follow-up `ExpandedNodeIdCodec`. This is consistent with
/// the existing `VariantCodec` simplification for `expandedNodeId`.
library;

import 'dart:typed_data';

import '../encoding/binary_reader.dart';
import '../encoding/binary_writer.dart';
import '../encoding/built_in_types.dart';
import '../encoding/node_id_codec.dart';
import 'request_header.dart';

/// Browse direction enum (Part 4 §7.5).
enum OpcUaBrowseDirection {
  forward(0),
  inverse(1),
  both(2);

  const OpcUaBrowseDirection(this.id);
  final int id;

  static OpcUaBrowseDirection fromId(int id) {
    if (id < 0 || id > 2) {
      throw ArgumentError.value(id, 'id', 'invalid BrowseDirection');
    }
    return OpcUaBrowseDirection.values[id];
  }
}

/// NodeClass bitmask (Part 4 §7.16). Use as `nodeClassMask` in
/// [OpcUaBrowseDescription] — `0` = all classes.
class OpcUaNodeClass {
  static const int unspecified = 0;
  static const int object = 1;
  static const int variable = 2;
  static const int method = 4;
  static const int objectType = 8;
  static const int variableType = 16;
  static const int referenceType = 32;
  static const int dataType = 64;
  static const int view = 128;
}

/// Selects which fields of [OpcUaReferenceDescription] are populated by the
/// server (Part 4 §7.4 BrowseResultMask).
class OpcUaBrowseResultMask {
  static const int none = 0;
  static const int referenceType = 0x01;
  static const int isForward = 0x02;
  static const int nodeClass = 0x04;
  static const int browseName = 0x08;
  static const int displayName = 0x10;
  static const int typeDefinition = 0x20;
  static const int all = 0x3F;
}

/// View identification — the null view (`viewId == null NodeId`,
/// timestamp = epoch, viewVersion = 0) selects the address space root.
class OpcUaViewDescription {
  final OpcUaNodeIdValue viewId;
  final DateTime timestamp;
  final int viewVersion;

  const OpcUaViewDescription({
    required this.viewId,
    required this.timestamp,
    this.viewVersion = 0,
  });

  factory OpcUaViewDescription.nullView() => OpcUaViewDescription(
        viewId: const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 0),
        timestamp: DateTime.utc(1601, 1, 1),
      );

  void encode(BinaryWriter w) {
    NodeIdCodec.encode(w, viewId);
    w.writeInt64(_dateTimeToTicks(timestamp));
    w.writeUint32(viewVersion);
  }

  factory OpcUaViewDescription.decode(BinaryReader r) {
    return OpcUaViewDescription(
      viewId: NodeIdCodec.decode(r),
      timestamp: _ticksToDateTime(r.readInt64()),
      viewVersion: r.readUint32(),
    );
  }
}

/// One node-to-browse entry (Part 4 §7.5).
class OpcUaBrowseDescription {
  final OpcUaNodeIdValue nodeId;
  final OpcUaBrowseDirection browseDirection;

  /// `null` NodeId means "no filtering by reference type".
  final OpcUaNodeIdValue referenceTypeId;

  final bool includeSubtypes;
  final int nodeClassMask;
  final int resultMask;

  const OpcUaBrowseDescription({
    required this.nodeId,
    this.browseDirection = OpcUaBrowseDirection.both,
    this.referenceTypeId =
        const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 0),
    this.includeSubtypes = true,
    this.nodeClassMask = OpcUaNodeClass.unspecified,
    this.resultMask = OpcUaBrowseResultMask.all,
  });

  void encode(BinaryWriter w) {
    NodeIdCodec.encode(w, nodeId);
    w.writeUint32(browseDirection.id);
    NodeIdCodec.encode(w, referenceTypeId);
    w.writeUint8(includeSubtypes ? 1 : 0);
    w.writeUint32(nodeClassMask);
    w.writeUint32(resultMask);
  }

  factory OpcUaBrowseDescription.decode(BinaryReader r) {
    return OpcUaBrowseDescription(
      nodeId: NodeIdCodec.decode(r),
      browseDirection: OpcUaBrowseDirection.fromId(r.readUint32()),
      referenceTypeId: NodeIdCodec.decode(r),
      includeSubtypes: r.readUint8() != 0,
      nodeClassMask: r.readUint32(),
      resultMask: r.readUint32(),
    );
  }
}

/// Per-row reference returned by Browse.
class OpcUaReferenceDescriptionWire {
  final OpcUaNodeIdValue referenceTypeId;
  final bool isForward;

  /// Encoded as a plain NodeId for now (no ExpandedNodeId flags).
  final OpcUaNodeIdValue nodeId;
  final OpcUaQualifiedName browseName;
  final OpcUaLocalizedText displayName;
  final int nodeClass;

  /// Encoded as a plain NodeId for now (no ExpandedNodeId flags).
  final OpcUaNodeIdValue typeDefinition;

  const OpcUaReferenceDescriptionWire({
    required this.referenceTypeId,
    required this.isForward,
    required this.nodeId,
    required this.browseName,
    required this.displayName,
    required this.nodeClass,
    required this.typeDefinition,
  });

  void encode(BinaryWriter w) {
    NodeIdCodec.encode(w, referenceTypeId);
    w.writeUint8(isForward ? 1 : 0);
    NodeIdCodec.encode(w, nodeId);
    w.writeUint16(browseName.namespaceIndex);
    w.writeStringOrNull(browseName.name);
    var ltMask = 0;
    if (displayName.locale != null) ltMask |= 0x01;
    if (displayName.text != null) ltMask |= 0x02;
    w.writeUint8(ltMask);
    if (displayName.locale != null) w.writeStringOrNull(displayName.locale);
    if (displayName.text != null) w.writeStringOrNull(displayName.text);
    w.writeUint32(nodeClass);
    NodeIdCodec.encode(w, typeDefinition);
  }

  factory OpcUaReferenceDescriptionWire.decode(BinaryReader r) {
    final refType = NodeIdCodec.decode(r);
    final isFwd = r.readUint8() != 0;
    final nodeId = NodeIdCodec.decode(r);
    final qnNs = r.readUint16();
    final qnName = r.readStringOrNull() ?? '';
    final ltMask = r.readUint8();
    String? locale;
    String? text;
    if ((ltMask & 0x01) != 0) locale = r.readStringOrNull();
    if ((ltMask & 0x02) != 0) text = r.readStringOrNull();
    final nodeClass = r.readUint32();
    final typeDef = NodeIdCodec.decode(r);
    return OpcUaReferenceDescriptionWire(
      referenceTypeId: refType,
      isForward: isFwd,
      nodeId: nodeId,
      browseName: OpcUaQualifiedName(namespaceIndex: qnNs, name: qnName),
      displayName: OpcUaLocalizedText(locale: locale, text: text),
      nodeClass: nodeClass,
      typeDefinition: typeDef,
    );
  }
}

class OpcUaBrowseResultRow {
  final int statusCode;
  final List<int>? continuationPoint;
  final List<OpcUaReferenceDescriptionWire> references;

  const OpcUaBrowseResultRow({
    this.statusCode = 0,
    this.continuationPoint,
    this.references = const [],
  });

  void encode(BinaryWriter w) {
    w.writeUint32(statusCode);
    w.writeByteStringOrNull(continuationPoint);
    w.writeInt32(references.length);
    for (final r in references) {
      r.encode(w);
    }
  }

  factory OpcUaBrowseResultRow.decode(BinaryReader r) {
    final status = r.readUint32();
    final cp = r.readByteStringOrNull();
    final n = r.readInt32();
    final refs = <OpcUaReferenceDescriptionWire>[
      for (var i = 0; i < n; i++) OpcUaReferenceDescriptionWire.decode(r),
    ];
    return OpcUaBrowseResultRow(
      statusCode: status,
      continuationPoint: cp,
      references: refs,
    );
  }
}

class OpcUaBrowseRequest {
  final OpcUaRequestHeader header;
  final OpcUaViewDescription view;
  final int requestedMaxReferencesPerNode;
  final List<OpcUaBrowseDescription> nodesToBrowse;

  const OpcUaBrowseRequest({
    required this.header,
    required this.view,
    this.requestedMaxReferencesPerNode = 0,
    required this.nodesToBrowse,
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    view.encode(w);
    w.writeUint32(requestedMaxReferencesPerNode);
    w.writeInt32(nodesToBrowse.length);
    for (final n in nodesToBrowse) {
      n.encode(w);
    }
  }

  factory OpcUaBrowseRequest.decode(BinaryReader r) {
    final header = OpcUaRequestHeader.decode(r);
    final view = OpcUaViewDescription.decode(r);
    final maxRefs = r.readUint32();
    final n = r.readInt32();
    final list = <OpcUaBrowseDescription>[
      for (var i = 0; i < n; i++) OpcUaBrowseDescription.decode(r),
    ];
    return OpcUaBrowseRequest(
      header: header,
      view: view,
      requestedMaxReferencesPerNode: maxRefs,
      nodesToBrowse: list,
    );
  }
}

class OpcUaBrowseResponse {
  final OpcUaResponseHeader header;
  final List<OpcUaBrowseResultRow> results;
  final List<int> diagnosticInfoMasks;

  const OpcUaBrowseResponse({
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

  factory OpcUaBrowseResponse.decode(BinaryReader r) {
    final header = OpcUaResponseHeader.decode(r);
    final n = r.readInt32();
    final rows = <OpcUaBrowseResultRow>[
      for (var i = 0; i < n; i++) OpcUaBrowseResultRow.decode(r),
    ];
    final dn = r.readInt32();
    final diag = <int>[];
    if (dn > 0) {
      for (var i = 0; i < dn; i++) {
        final m = r.readUint8();
        if (m != 0) {
          throw StateError(
            'OpcUaBrowseResponse: non-empty DiagnosticInfo not supported',
          );
        }
        diag.add(m);
      }
    }
    return OpcUaBrowseResponse(
      header: header, results: rows, diagnosticInfoMasks: diag,
    );
  }
}

const int _epochOffsetMicros = -11644473600000000;

int _dateTimeToTicks(DateTime dt) =>
    (dt.toUtc().microsecondsSinceEpoch - _epochOffsetMicros) * 10;

DateTime _ticksToDateTime(int ticks) =>
    DateTime.fromMicrosecondsSinceEpoch(
        (ticks ~/ 10) + _epochOffsetMicros, isUtc: true);

// Avoid unused-import lint until ExpandedNodeId helpers land.
// ignore: unused_element
void _retain(Uint8List _) {}
