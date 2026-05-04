import 'dart:typed_data';

import 'binary_reader.dart';
import 'binary_writer.dart';
import 'built_in_types.dart';

/// Encoding mask for OPC UA NodeId (Part 6 §5.2.2.9).
class NodeIdEncodingMask {
  static const int twoByte = 0x00;
  static const int fourByte = 0x01;
  static const int numeric = 0x02;
  static const int string = 0x03;
  static const int guid = 0x04;
  static const int byteString = 0x05;
}

/// Five NodeId encodings per Part 6 §5.2.2.9.
sealed class OpcUaNodeIdValue {
  const OpcUaNodeIdValue();

  int get namespaceIndex;
}

class OpcUaNodeIdNumeric extends OpcUaNodeIdValue {
  const OpcUaNodeIdNumeric({
    required this.namespaceIndex,
    required this.identifier,
  });

  @override
  final int namespaceIndex;

  /// 0..2^32-1.
  final int identifier;

  @override
  bool operator ==(Object other) =>
      other is OpcUaNodeIdNumeric &&
      other.namespaceIndex == namespaceIndex &&
      other.identifier == identifier;

  @override
  int get hashCode => Object.hash(namespaceIndex, identifier);

  @override
  String toString() => 'ns=$namespaceIndex;i=$identifier';
}

class OpcUaNodeIdString extends OpcUaNodeIdValue {
  const OpcUaNodeIdString({
    required this.namespaceIndex,
    required this.identifier,
  });

  @override
  final int namespaceIndex;
  final String identifier;

  @override
  bool operator ==(Object other) =>
      other is OpcUaNodeIdString &&
      other.namespaceIndex == namespaceIndex &&
      other.identifier == identifier;

  @override
  int get hashCode => Object.hash(namespaceIndex, identifier);

  @override
  String toString() => 'ns=$namespaceIndex;s=$identifier';
}

class OpcUaNodeIdGuid extends OpcUaNodeIdValue {
  const OpcUaNodeIdGuid({
    required this.namespaceIndex,
    required this.identifier,
  });

  @override
  final int namespaceIndex;
  final OpcUaGuid identifier;

  @override
  bool operator ==(Object other) =>
      other is OpcUaNodeIdGuid &&
      other.namespaceIndex == namespaceIndex &&
      other.identifier == identifier;

  @override
  int get hashCode => Object.hash(namespaceIndex, identifier);

  @override
  String toString() => 'ns=$namespaceIndex;g=$identifier';
}

class OpcUaNodeIdByteString extends OpcUaNodeIdValue {
  OpcUaNodeIdByteString({
    required this.namespaceIndex,
    required List<int> identifier,
  }) : identifier = Uint8List.fromList(identifier);

  @override
  final int namespaceIndex;
  final Uint8List identifier;

  @override
  bool operator ==(Object other) {
    if (other is! OpcUaNodeIdByteString) return false;
    if (other.namespaceIndex != namespaceIndex) return false;
    if (other.identifier.length != identifier.length) return false;
    for (var i = 0; i < identifier.length; i++) {
      if (other.identifier[i] != identifier[i]) return false;
    }
    return true;
  }

  @override
  int get hashCode => Object.hash(namespaceIndex, Object.hashAll(identifier));

  @override
  String toString() => 'ns=$namespaceIndex;b=${identifier.length}b';
}

class NodeIdCodec {
  NodeIdCodec._();

  /// Encode using the most compact form that fits.
  ///
  /// - TwoByte (0x00) when ns=0 and identifier <= 255 (numeric only)
  /// - FourByte (0x01) when ns < 256 and identifier <= 65535 (numeric)
  /// - Numeric (0x02) for any other numeric
  /// - String (0x03), Guid (0x04), ByteString (0x05) for those kinds
  static void encode(BinaryWriter w, OpcUaNodeIdValue node) {
    if (node is OpcUaNodeIdNumeric) {
      if (node.namespaceIndex == 0 && node.identifier <= 0xFF) {
        w.writeUint8(NodeIdEncodingMask.twoByte);
        w.writeUint8(node.identifier);
        return;
      }
      if (node.namespaceIndex <= 0xFF && node.identifier <= 0xFFFF) {
        w.writeUint8(NodeIdEncodingMask.fourByte);
        w.writeUint8(node.namespaceIndex);
        w.writeUint16(node.identifier);
        return;
      }
      w.writeUint8(NodeIdEncodingMask.numeric);
      w.writeUint16(node.namespaceIndex);
      w.writeUint32(node.identifier);
      return;
    }
    if (node is OpcUaNodeIdString) {
      w.writeUint8(NodeIdEncodingMask.string);
      w.writeUint16(node.namespaceIndex);
      w.writeStringOrNull(node.identifier);
      return;
    }
    if (node is OpcUaNodeIdGuid) {
      w.writeUint8(NodeIdEncodingMask.guid);
      w.writeUint16(node.namespaceIndex);
      w.writeBytes(node.identifier.bytes);
      return;
    }
    if (node is OpcUaNodeIdByteString) {
      w.writeUint8(NodeIdEncodingMask.byteString);
      w.writeUint16(node.namespaceIndex);
      w.writeByteStringOrNull(node.identifier);
      return;
    }
    throw ArgumentError.value(node, 'node', 'unsupported NodeId kind');
  }

  static OpcUaNodeIdValue decode(BinaryReader r) {
    final mask = r.readUint8();
    switch (mask & 0x3F) {
      case NodeIdEncodingMask.twoByte:
        return OpcUaNodeIdNumeric(
            namespaceIndex: 0, identifier: r.readUint8());
      case NodeIdEncodingMask.fourByte:
        final ns = r.readUint8();
        final id = r.readUint16();
        return OpcUaNodeIdNumeric(namespaceIndex: ns, identifier: id);
      case NodeIdEncodingMask.numeric:
        final ns = r.readUint16();
        final id = r.readUint32();
        return OpcUaNodeIdNumeric(namespaceIndex: ns, identifier: id);
      case NodeIdEncodingMask.string:
        final ns = r.readUint16();
        final id = r.readStringOrNull();
        return OpcUaNodeIdString(namespaceIndex: ns, identifier: id ?? '');
      case NodeIdEncodingMask.guid:
        final ns = r.readUint16();
        final raw = r.readBytes(16);
        return OpcUaNodeIdGuid(
            namespaceIndex: ns, identifier: OpcUaGuid(raw));
      case NodeIdEncodingMask.byteString:
        final ns = r.readUint16();
        final raw = r.readByteStringOrNull() ?? Uint8List(0);
        return OpcUaNodeIdByteString(
            namespaceIndex: ns, identifier: raw);
      default:
        throw FormatException(
            'unsupported NodeId encoding mask: 0x${mask.toRadixString(16)}');
    }
  }
}
