/// OPC UA built-in type identifiers per Part 6 §5.1.
///
/// These IDs appear in the lower 6 bits of a Variant's encoding mask
/// and as the `BuiltInType` field of a DataType description.
enum OpcUaBuiltInType {
  null_(0),
  boolean(1),
  sByte(2),
  byte(3),
  int16(4),
  uInt16(5),
  int32(6),
  uInt32(7),
  int64(8),
  uInt64(9),
  float(10),
  double_(11),
  string(12),
  dateTime(13),
  guid(14),
  byteString(15),
  xmlElement(16),
  nodeId(17),
  expandedNodeId(18),
  statusCode(19),
  qualifiedName(20),
  localizedText(21),
  extensionObject(22),
  dataValue(23),
  variant(24),
  diagnosticInfo(25);

  const OpcUaBuiltInType(this.id);

  final int id;

  static OpcUaBuiltInType fromId(int id) {
    if (id < 0 || id > 25) {
      throw ArgumentError.value(id, 'id', 'invalid built-in type id');
    }
    return OpcUaBuiltInType.values[id];
  }
}

/// 16-byte GUID (UUID) — OPC UA Part 6 §5.1.3.
class OpcUaGuid {
  /// 16 raw bytes in OPC UA layout (Data1 LE, Data2 LE, Data3 LE,
  /// Data4 raw).
  const OpcUaGuid(this.bytes);

  factory OpcUaGuid.fromString(String s) {
    // Standard UUID form: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    final clean = s.replaceAll('-', '');
    if (clean.length != 32) {
      throw FormatException('invalid GUID: $s');
    }
    final out = List<int>.filled(16, 0);
    for (var i = 0; i < 16; i++) {
      out[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return OpcUaGuid(out);
  }

  final List<int> bytes;

  String toStandardString() {
    String hex(int n) => n.toRadixString(16).padLeft(2, '0');
    final h = bytes.map(hex).join();
    return '${h.substring(0, 8)}-${h.substring(8, 12)}-'
        '${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20)}';
  }

  @override
  bool operator ==(Object other) =>
      other is OpcUaGuid &&
      other.bytes.length == bytes.length &&
      List.generate(16, (i) => other.bytes[i] == bytes[i])
          .every((eq) => eq);

  @override
  int get hashCode => Object.hashAll(bytes);

  @override
  String toString() => toStandardString();
}

/// QualifiedName — namespace-qualified short name (e.g. browse names).
class OpcUaQualifiedName {
  const OpcUaQualifiedName({required this.namespaceIndex, required this.name});

  final int namespaceIndex;
  final String name;

  @override
  bool operator ==(Object other) =>
      other is OpcUaQualifiedName &&
      other.namespaceIndex == namespaceIndex &&
      other.name == name;

  @override
  int get hashCode => Object.hash(namespaceIndex, name);

  @override
  String toString() => 'ns=$namespaceIndex;qn=$name';
}

/// LocalizedText — locale-tagged human-readable text.
class OpcUaLocalizedText {
  const OpcUaLocalizedText({this.locale, this.text});

  final String? locale;
  final String? text;

  @override
  bool operator ==(Object other) =>
      other is OpcUaLocalizedText &&
      other.locale == locale &&
      other.text == text;

  @override
  int get hashCode => Object.hash(locale, text);
}

/// StatusCode — 32-bit unsigned. The high 16 bits encode severity +
/// sub-code; the low 16 bits encode info bits.
class OpcUaStatusCode {
  const OpcUaStatusCode(this.value);

  final int value;

  static const OpcUaStatusCode good = OpcUaStatusCode(0);

  /// Severity (bits 30..31): Good (00), Uncertain (01), Bad (10).
  int get severity => (value >> 30) & 0x3;

  bool get isGood => severity == 0;
  bool get isUncertain => severity == 1;
  bool get isBad => severity == 2;

  @override
  bool operator ==(Object other) =>
      other is OpcUaStatusCode && other.value == value;

  @override
  int get hashCode => value.hashCode;

  @override
  String toString() =>
      'StatusCode(0x${value.toRadixString(16).padLeft(8, '0')})';
}
