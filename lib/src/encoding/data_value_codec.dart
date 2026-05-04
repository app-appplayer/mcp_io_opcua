import 'binary_reader.dart';
import 'binary_writer.dart';
import 'built_in_types.dart';
import 'variant_codec.dart';

/// DataValue mask bits (Part 6 §5.2.2.17).
class _DataValueMask {
  static const int hasValue = 0x01;
  static const int hasStatus = 0x02;
  static const int hasSourceTimestamp = 0x04;
  static const int hasServerTimestamp = 0x08;
  static const int hasSourcePicoseconds = 0x10;
  static const int hasServerPicoseconds = 0x20;
}

/// OPC UA DataValue (Variant + status + timestamps).
class OpcUaDataValue {
  const OpcUaDataValue({
    this.value,
    this.status,
    this.sourceTimestamp,
    this.sourcePicoseconds,
    this.serverTimestamp,
    this.serverPicoseconds,
  });

  final OpcUaVariantValue? value;
  final OpcUaStatusCode? status;
  final DateTime? sourceTimestamp;
  final int? sourcePicoseconds;
  final DateTime? serverTimestamp;
  final int? serverPicoseconds;
}

class DataValueCodec {
  DataValueCodec._();

  static void encode(BinaryWriter w, OpcUaDataValue dv) {
    var mask = 0;
    if (dv.value != null && !dv.value!.isEmpty) mask |= _DataValueMask.hasValue;
    if (dv.status != null) mask |= _DataValueMask.hasStatus;
    if (dv.sourceTimestamp != null) mask |= _DataValueMask.hasSourceTimestamp;
    if (dv.serverTimestamp != null) mask |= _DataValueMask.hasServerTimestamp;
    if (dv.sourcePicoseconds != null) {
      mask |= _DataValueMask.hasSourcePicoseconds;
    }
    if (dv.serverPicoseconds != null) {
      mask |= _DataValueMask.hasServerPicoseconds;
    }
    w.writeUint8(mask);

    if ((mask & _DataValueMask.hasValue) != 0) {
      VariantCodec.encode(w, dv.value!);
    }
    if ((mask & _DataValueMask.hasStatus) != 0) {
      w.writeUint32(dv.status!.value);
    }
    if ((mask & _DataValueMask.hasSourceTimestamp) != 0) {
      w.writeInt64(_dateTimeToTicks(dv.sourceTimestamp!));
    }
    if ((mask & _DataValueMask.hasSourcePicoseconds) != 0) {
      w.writeUint16(dv.sourcePicoseconds!);
    }
    if ((mask & _DataValueMask.hasServerTimestamp) != 0) {
      w.writeInt64(_dateTimeToTicks(dv.serverTimestamp!));
    }
    if ((mask & _DataValueMask.hasServerPicoseconds) != 0) {
      w.writeUint16(dv.serverPicoseconds!);
    }
  }

  static OpcUaDataValue decode(BinaryReader r) {
    final mask = r.readUint8();
    OpcUaVariantValue? value;
    OpcUaStatusCode? status;
    DateTime? srcTs;
    int? srcPicos;
    DateTime? svrTs;
    int? svrPicos;

    if ((mask & _DataValueMask.hasValue) != 0) {
      value = VariantCodec.decode(r);
    }
    if ((mask & _DataValueMask.hasStatus) != 0) {
      status = OpcUaStatusCode(r.readUint32());
    }
    if ((mask & _DataValueMask.hasSourceTimestamp) != 0) {
      srcTs = _ticksToDateTime(r.readInt64());
    }
    if ((mask & _DataValueMask.hasSourcePicoseconds) != 0) {
      srcPicos = r.readUint16();
    }
    if ((mask & _DataValueMask.hasServerTimestamp) != 0) {
      svrTs = _ticksToDateTime(r.readInt64());
    }
    if ((mask & _DataValueMask.hasServerPicoseconds) != 0) {
      svrPicos = r.readUint16();
    }
    return OpcUaDataValue(
      value: value,
      status: status,
      sourceTimestamp: srcTs,
      sourcePicoseconds: srcPicos,
      serverTimestamp: svrTs,
      serverPicoseconds: svrPicos,
    );
  }

  // 100-ns ticks since 1601-01-01 UTC.
  static const int _epochOffsetMicros = -11644473600000000;

  static int _dateTimeToTicks(DateTime dt) =>
      (dt.toUtc().microsecondsSinceEpoch - _epochOffsetMicros) * 10;

  static DateTime _ticksToDateTime(int ticks) =>
      DateTime.fromMicrosecondsSinceEpoch(
          (ticks ~/ 10) + _epochOffsetMicros,
          isUtc: true);
}
