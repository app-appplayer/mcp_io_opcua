import 'dart:typed_data';

import 'binary_reader.dart';
import 'binary_writer.dart';
import 'node_id_codec.dart';

/// Body encoding kind for ExtensionObject (Part 6 §5.2.2.15).
enum ExtensionObjectEncoding {
  noBody(0x00),
  byteString(0x01),
  xmlElement(0x02);

  const ExtensionObjectEncoding(this.id);
  final int id;

  static ExtensionObjectEncoding fromId(int id) {
    switch (id) {
      case 0x00:
        return ExtensionObjectEncoding.noBody;
      case 0x01:
        return ExtensionObjectEncoding.byteString;
      case 0x02:
        return ExtensionObjectEncoding.xmlElement;
      default:
        throw FormatException(
            'invalid ExtensionObject encoding: 0x${id.toRadixString(16)}');
    }
  }
}

/// Wraps a server-defined struct.
///
/// The body is opaque bytes (or XML); higher layers (e.g. application
/// code that knows the struct's binary layout) decode the body.
class OpcUaExtensionObject {
  const OpcUaExtensionObject({
    required this.typeId,
    required this.encoding,
    this.body,
  });

  /// NodeId of the structure's DataType (binary encoding form).
  final OpcUaNodeIdValue typeId;

  final ExtensionObjectEncoding encoding;

  /// Raw body bytes (UTF-8 XML when encoding is xmlElement, opaque
  /// otherwise). `null` when encoding is `noBody`.
  final Uint8List? body;
}

class ExtensionObjectCodec {
  ExtensionObjectCodec._();

  static void encode(BinaryWriter w, OpcUaExtensionObject eo) {
    NodeIdCodec.encode(w, eo.typeId);
    w.writeUint8(eo.encoding.id);
    if (eo.encoding == ExtensionObjectEncoding.noBody) return;
    w.writeByteStringOrNull(eo.body);
  }

  static OpcUaExtensionObject decode(BinaryReader r) {
    final typeId = NodeIdCodec.decode(r);
    final encoding = ExtensionObjectEncoding.fromId(r.readUint8());
    Uint8List? body;
    if (encoding != ExtensionObjectEncoding.noBody) {
      body = r.readByteStringOrNull();
    }
    return OpcUaExtensionObject(
        typeId: typeId, encoding: encoding, body: body);
  }
}
