import 'dart:typed_data';

import 'binary_reader.dart';
import 'binary_writer.dart';
import 'built_in_types.dart';
import 'node_id_codec.dart';

/// Variant value with its associated [OpcUaBuiltInType].
///
/// Spec ref: OPC UA Part 6 §5.2.2.16.
class OpcUaVariantValue {
  const OpcUaVariantValue({
    required this.type,
    required this.value,
    this.isArrayValue = false,
    this.dimensions,
  });

  /// Empty / null variant (mask = 0).
  static const empty =
      OpcUaVariantValue(type: OpcUaBuiltInType.null_, value: null);

  factory OpcUaVariantValue.scalar(OpcUaBuiltInType type, Object? value) =>
      OpcUaVariantValue(type: type, value: value);

  factory OpcUaVariantValue.array(
    OpcUaBuiltInType type,
    List<Object?> values,
  ) =>
      OpcUaVariantValue(type: type, value: values, isArrayValue: true);

  factory OpcUaVariantValue.matrix(
    OpcUaBuiltInType type,
    List<Object?> flat,
    List<int> dims,
  ) =>
      OpcUaVariantValue(
        type: type,
        value: flat,
        isArrayValue: true,
        dimensions: dims,
      );

  final OpcUaBuiltInType type;

  /// Either a scalar (`int`, `double`, `String`, `List<int>` for
  /// ByteString, ...) or a `List<Object?>` for arrays / matrices. Use
  /// [isArrayValue] to distinguish — a `List<int>` ByteString scalar
  /// is not an array.
  final Object? value;

  /// Explicit array/matrix marker (mask bit 7). Required because some
  /// scalar built-ins (`ByteString`) are themselves list-typed in
  /// Dart.
  final bool isArrayValue;

  /// Multi-dim shape for matrices. `null` for scalars and 1-D arrays.
  final List<int>? dimensions;

  bool get isArray => isArrayValue;
  bool get isMatrix => dimensions != null;
  bool get isEmpty => type == OpcUaBuiltInType.null_;
}

/// Encoding mask bits for Variant (Part 6 §5.2.2.16).
class _VariantMask {
  static const int builtInTypeMask = 0x3F;
  static const int hasArrayDimensions = 0x40;
  static const int isArray = 0x80;
}

class VariantCodec {
  VariantCodec._();

  static void encode(BinaryWriter w, OpcUaVariantValue v) {
    if (v.isEmpty) {
      w.writeUint8(0);
      return;
    }
    var mask = v.type.id & _VariantMask.builtInTypeMask;
    if (v.isArray) mask |= _VariantMask.isArray;
    if (v.isMatrix) mask |= _VariantMask.hasArrayDimensions;
    w.writeUint8(mask);

    if (v.isArray) {
      final list = v.value as List<Object?>;
      w.writeInt32(list.length);
      for (final element in list) {
        _writeScalar(w, v.type, element);
      }
      if (v.isMatrix) {
        final dims = v.dimensions!;
        w.writeInt32(dims.length);
        for (final d in dims) {
          w.writeInt32(d);
        }
      }
    } else {
      _writeScalar(w, v.type, v.value);
    }
  }

  static OpcUaVariantValue decode(BinaryReader r) {
    final mask = r.readUint8();
    if (mask == 0) return OpcUaVariantValue.empty;
    final typeId = mask & _VariantMask.builtInTypeMask;
    final type = OpcUaBuiltInType.fromId(typeId);
    final isArray = (mask & _VariantMask.isArray) != 0;
    final hasDims = (mask & _VariantMask.hasArrayDimensions) != 0;

    if (!isArray) {
      return OpcUaVariantValue(type: type, value: _readScalar(r, type));
    }
    final length = r.readInt32();
    final list = <Object?>[];
    if (length >= 0) {
      for (var i = 0; i < length; i++) {
        list.add(_readScalar(r, type));
      }
    }
    List<int>? dims;
    if (hasDims) {
      final dimsLen = r.readInt32();
      if (dimsLen >= 0) {
        dims = List<int>.generate(dimsLen, (_) => r.readInt32());
      }
    }
    return OpcUaVariantValue(
      type: type,
      value: list,
      isArrayValue: true,
      dimensions: dims,
    );
  }

  // -------------------------------------------------------------------------
  // Scalar value codec per built-in type
  // -------------------------------------------------------------------------

  static void _writeScalar(
      BinaryWriter w, OpcUaBuiltInType type, Object? value) {
    switch (type) {
      case OpcUaBuiltInType.null_:
        return; // no body
      case OpcUaBuiltInType.boolean:
        w.writeUint8((value as bool) ? 1 : 0);
      case OpcUaBuiltInType.sByte:
        w.writeInt8(value as int);
      case OpcUaBuiltInType.byte:
        w.writeUint8(value as int);
      case OpcUaBuiltInType.int16:
        w.writeInt16(value as int);
      case OpcUaBuiltInType.uInt16:
        w.writeUint16(value as int);
      case OpcUaBuiltInType.int32:
        w.writeInt32(value as int);
      case OpcUaBuiltInType.uInt32:
        w.writeUint32(value as int);
      case OpcUaBuiltInType.int64:
        w.writeInt64(value as int);
      case OpcUaBuiltInType.uInt64:
        w.writeUint64(value as int);
      case OpcUaBuiltInType.float:
        w.writeFloat32((value as num).toDouble());
      case OpcUaBuiltInType.double_:
        w.writeFloat64((value as num).toDouble());
      case OpcUaBuiltInType.string:
        w.writeStringOrNull(value as String?);
      case OpcUaBuiltInType.dateTime:
        // OPC UA DateTime: 100-ns ticks since 1601-01-01 UTC.
        final dt = value as DateTime;
        w.writeInt64(_dateTimeToTicks(dt));
      case OpcUaBuiltInType.guid:
        final g = value as OpcUaGuid;
        w.writeBytes(g.bytes);
      case OpcUaBuiltInType.byteString:
        w.writeByteStringOrNull(value as List<int>?);
      case OpcUaBuiltInType.xmlElement:
        w.writeStringOrNull(value as String?);
      case OpcUaBuiltInType.nodeId:
        NodeIdCodec.encode(w, value as OpcUaNodeIdValue);
      case OpcUaBuiltInType.expandedNodeId:
        // Encoded same as NodeId for the inner part; namespaceUri /
        // serverIndex are advanced features deferred to v1.x.
        NodeIdCodec.encode(w, value as OpcUaNodeIdValue);
      case OpcUaBuiltInType.statusCode:
        w.writeUint32((value as OpcUaStatusCode).value);
      case OpcUaBuiltInType.qualifiedName:
        final q = value as OpcUaQualifiedName;
        w.writeUint16(q.namespaceIndex);
        w.writeStringOrNull(q.name);
      case OpcUaBuiltInType.localizedText:
        final lt = value as OpcUaLocalizedText;
        var encoMask = 0;
        if (lt.locale != null) encoMask |= 0x01;
        if (lt.text != null) encoMask |= 0x02;
        w.writeUint8(encoMask);
        if (lt.locale != null) w.writeStringOrNull(lt.locale);
        if (lt.text != null) w.writeStringOrNull(lt.text);
      case OpcUaBuiltInType.extensionObject:
        // ExtensionObject codec lives in its own file; pass-through.
        // Callers should normally use ExtensionObjectCodec.encode but
        // having a Variant-of-ExtensionObject is also valid spec.
        throw UnsupportedError(
            'ExtensionObject inside Variant — use ExtensionObjectCodec at the '
            'top level (deferred for v1.x)');
      case OpcUaBuiltInType.dataValue:
        throw UnsupportedError(
            'DataValue inside Variant — deferred for v1.x');
      case OpcUaBuiltInType.variant:
        encode(w, value as OpcUaVariantValue);
      case OpcUaBuiltInType.diagnosticInfo:
        throw UnsupportedError('DiagnosticInfo encoding deferred for v1.x');
    }
  }

  static Object? _readScalar(BinaryReader r, OpcUaBuiltInType type) {
    switch (type) {
      case OpcUaBuiltInType.null_:
        return null;
      case OpcUaBuiltInType.boolean:
        return r.readUint8() != 0;
      case OpcUaBuiltInType.sByte:
        return r.readInt8();
      case OpcUaBuiltInType.byte:
        return r.readUint8();
      case OpcUaBuiltInType.int16:
        return r.readInt16();
      case OpcUaBuiltInType.uInt16:
        return r.readUint16();
      case OpcUaBuiltInType.int32:
        return r.readInt32();
      case OpcUaBuiltInType.uInt32:
        return r.readUint32();
      case OpcUaBuiltInType.int64:
        return r.readInt64();
      case OpcUaBuiltInType.uInt64:
        return r.readUint64();
      case OpcUaBuiltInType.float:
        return r.readFloat32();
      case OpcUaBuiltInType.double_:
        return r.readFloat64();
      case OpcUaBuiltInType.string:
        return r.readStringOrNull();
      case OpcUaBuiltInType.dateTime:
        return _ticksToDateTime(r.readInt64());
      case OpcUaBuiltInType.guid:
        return OpcUaGuid(r.readBytes(16));
      case OpcUaBuiltInType.byteString:
        return r.readByteStringOrNull();
      case OpcUaBuiltInType.xmlElement:
        return r.readStringOrNull();
      case OpcUaBuiltInType.nodeId:
        return NodeIdCodec.decode(r);
      case OpcUaBuiltInType.expandedNodeId:
        return NodeIdCodec.decode(r);
      case OpcUaBuiltInType.statusCode:
        return OpcUaStatusCode(r.readUint32());
      case OpcUaBuiltInType.qualifiedName:
        final ns = r.readUint16();
        final name = r.readStringOrNull() ?? '';
        return OpcUaQualifiedName(namespaceIndex: ns, name: name);
      case OpcUaBuiltInType.localizedText:
        final mask = r.readUint8();
        String? locale;
        String? text;
        if ((mask & 0x01) != 0) locale = r.readStringOrNull();
        if ((mask & 0x02) != 0) text = r.readStringOrNull();
        return OpcUaLocalizedText(locale: locale, text: text);
      case OpcUaBuiltInType.extensionObject:
        throw UnsupportedError('ExtensionObject decoded via dedicated codec');
      case OpcUaBuiltInType.dataValue:
        throw UnsupportedError('DataValue decoded via dedicated codec');
      case OpcUaBuiltInType.variant:
        return decode(r);
      case OpcUaBuiltInType.diagnosticInfo:
        throw UnsupportedError('DiagnosticInfo decoding deferred for v1.x');
    }
  }

  // -------------------------------------------------------------------------
  // DateTime conversion
  // -------------------------------------------------------------------------

  /// 1601-01-01 UTC in microseconds-since-epoch (Dart's DateTime origin).
  /// `(1601-01-01 - 1970-01-01).inMicroseconds = -11_644_473_600_000_000`
  static const int _epochOffsetMicros = -11644473600000000;

  static int _dateTimeToTicks(DateTime dt) {
    final micros = dt.toUtc().microsecondsSinceEpoch - _epochOffsetMicros;
    return micros * 10; // 100-ns ticks
  }

  static DateTime _ticksToDateTime(int ticks) {
    final micros = (ticks ~/ 10) + _epochOffsetMicros;
    return DateTime.fromMicrosecondsSinceEpoch(micros, isUtc: true);
  }
}

// Keep dart:typed_data import alive (BinaryReader/Writer use it via deps).
// ignore: unused_element
Uint8List _kUnusedRef() => Uint8List(0);
