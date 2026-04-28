/// Core OPC UA value types needed by the MVP adapter.
///
/// The OPC UA specification has a very rich type system (Variant, DataValue,
/// ExtensionObject, StructuredType ...). This MVP implements only the slices
/// required to read/write scalar node values.
library;

/// Identifier type tags per OPC UA Part 6 § 5.2.2.9.
enum OpcUaNodeIdKind { numeric, string }

/// OPC UA NodeId — identifies a single addressable item in the server's
/// address space. Always namespaced; a numeric namespace index of 0 refers
/// to the OPC Foundation standard namespace.
class OpcUaNodeId {
  final int namespace;
  final OpcUaNodeIdKind kind;
  final int? numericId;
  final String? stringId;

  const OpcUaNodeId.numeric({
    required this.namespace,
    required int identifier,
  })  : kind = OpcUaNodeIdKind.numeric,
        numericId = identifier,
        stringId = null;

  const OpcUaNodeId.string({
    required this.namespace,
    required String identifier,
  })  : kind = OpcUaNodeIdKind.string,
        numericId = null,
        stringId = identifier;

  /// Standard human-readable form, e.g. `ns=2;i=1001` or `ns=3;s=MyTag`.
  String toStandardString() {
    switch (kind) {
      case OpcUaNodeIdKind.numeric:
        return 'ns=$namespace;i=$numericId';
      case OpcUaNodeIdKind.string:
        return 'ns=$namespace;s=$stringId';
    }
  }

  /// Parse a NodeId from its standard string form. Accepts the namespace
  /// prefix to be omitted (defaults to 0). Accepts both `i=` (numeric) and
  /// `s=` (string) identifier tokens.
  factory OpcUaNodeId.parse(String s) {
    final parts = s.split(';');
    var namespace = 0;
    String? identPart;
    for (final p in parts) {
      if (p.startsWith('ns=')) {
        namespace = int.parse(p.substring(3));
      } else {
        identPart = p;
      }
    }
    if (identPart == null) {
      throw FormatException('OpcUaNodeId missing identifier: $s');
    }
    if (identPart.startsWith('i=')) {
      final v = int.parse(identPart.substring(2));
      return OpcUaNodeId.numeric(namespace: namespace, identifier: v);
    }
    if (identPart.startsWith('s=')) {
      return OpcUaNodeId.string(
        namespace: namespace, identifier: identPart.substring(2),
      );
    }
    throw FormatException('OpcUaNodeId unsupported identifier kind: $s');
  }

  @override
  bool operator ==(Object other) =>
      other is OpcUaNodeId &&
      other.namespace == namespace &&
      other.kind == kind &&
      other.numericId == numericId &&
      other.stringId == stringId;

  @override
  int get hashCode => Object.hash(namespace, kind, numericId, stringId);

  @override
  String toString() => toStandardString();
}

/// Scalar variant tag set supported by the MVP.
enum OpcUaVariantKind {
  nullKind,
  boolean,
  int32,
  int64,
  double,
  string,
  bytes,
}

/// OPC UA Variant — a tagged scalar value. The MVP only supports scalar
/// forms; arrays / matrices are follow-up work.
class OpcUaVariant {
  final OpcUaVariantKind kind;
  final Object? value;

  const OpcUaVariant.nullValue()
      : kind = OpcUaVariantKind.nullKind, value = null;
  const OpcUaVariant.boolean(bool v)
      : kind = OpcUaVariantKind.boolean, value = v;
  const OpcUaVariant.int32(int v)
      : kind = OpcUaVariantKind.int32, value = v;
  const OpcUaVariant.int64(int v)
      : kind = OpcUaVariantKind.int64, value = v;
  const OpcUaVariant.double(double v)
      : kind = OpcUaVariantKind.double, value = v;
  const OpcUaVariant.string(String v)
      : kind = OpcUaVariantKind.string, value = v;
  const OpcUaVariant.bytes(List<int> v)
      : kind = OpcUaVariantKind.bytes, value = v;

  /// Best-effort conversion from a Dart value to a variant. Unrecognised
  /// types fall back to string via `toString()`.
  factory OpcUaVariant.fromDart(Object? v) {
    if (v == null) return const OpcUaVariant.nullValue();
    if (v is bool) return OpcUaVariant.boolean(v);
    if (v is int) {
      return (v >= -2147483648 && v <= 2147483647)
          ? OpcUaVariant.int32(v)
          : OpcUaVariant.int64(v);
    }
    if (v is double) return OpcUaVariant.double(v);
    if (v is String) return OpcUaVariant.string(v);
    if (v is List<int>) return OpcUaVariant.bytes(v);
    return OpcUaVariant.string(v.toString());
  }
}

class OpcUaProtocolError implements Exception {
  final String message;
  const OpcUaProtocolError(this.message);
  @override
  String toString() => 'OpcUaProtocolError: $message';
}
