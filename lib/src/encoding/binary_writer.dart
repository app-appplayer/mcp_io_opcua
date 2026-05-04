import 'dart:typed_data';

/// Little-endian binary writer with a growing buffer.
class BinaryWriter {
  factory BinaryWriter([int initialCapacity = 256]) {
    final buf = Uint8List(initialCapacity);
    return BinaryWriter._(buf, ByteData.sublistView(buf));
  }

  BinaryWriter._(this._buf, this._view);

  Uint8List _buf;
  ByteData _view;
  int _offset = 0;

  int get length => _offset;

  /// Take ownership of the encoded bytes.
  Uint8List takeBytes() => Uint8List.fromList(_buf.sublist(0, _offset));

  /// Snapshot of the current bytes without consuming the writer.
  Uint8List snapshot() => Uint8List.fromList(_buf.sublist(0, _offset));

  void _grow(int needed) {
    if (_offset + needed <= _buf.length) return;
    var newCap = _buf.length;
    while (newCap < _offset + needed) {
      newCap = newCap < 16 ? 16 : newCap * 2;
    }
    final next = Uint8List(newCap)..setAll(0, _buf.sublist(0, _offset));
    _buf = next;
    _view = ByteData.sublistView(_buf);
  }

  void writeUint8(int v) {
    _grow(1);
    _view.setUint8(_offset, v & 0xFF);
    _offset += 1;
  }

  void writeInt8(int v) {
    _grow(1);
    _view.setInt8(_offset, v);
    _offset += 1;
  }

  void writeUint16(int v) {
    _grow(2);
    _view.setUint16(_offset, v & 0xFFFF, Endian.little);
    _offset += 2;
  }

  void writeInt16(int v) {
    _grow(2);
    _view.setInt16(_offset, v, Endian.little);
    _offset += 2;
  }

  void writeUint32(int v) {
    _grow(4);
    _view.setUint32(_offset, v & 0xFFFFFFFF, Endian.little);
    _offset += 4;
  }

  void writeInt32(int v) {
    _grow(4);
    _view.setInt32(_offset, v, Endian.little);
    _offset += 4;
  }

  void writeUint64(int v) {
    _grow(8);
    _view.setUint64(_offset, v, Endian.little);
    _offset += 8;
  }

  void writeInt64(int v) {
    _grow(8);
    _view.setInt64(_offset, v, Endian.little);
    _offset += 8;
  }

  void writeFloat32(double v) {
    _grow(4);
    _view.setFloat32(_offset, v, Endian.little);
    _offset += 4;
  }

  void writeFloat64(double v) {
    _grow(8);
    _view.setFloat64(_offset, v, Endian.little);
    _offset += 8;
  }

  void writeBytes(List<int> b) {
    _grow(b.length);
    _buf.setAll(_offset, b);
    _offset += b.length;
  }

  /// Write an OPC UA String / ByteString (int32 length LE; -1 = null,
  /// followed by raw bytes when length >= 0).
  void writeByteStringOrNull(List<int>? data) {
    if (data == null) {
      writeInt32(-1);
      return;
    }
    writeInt32(data.length);
    writeBytes(data);
  }

  void writeStringOrNull(String? s) {
    if (s == null) {
      writeInt32(-1);
      return;
    }
    final bytes = s.codeUnits;
    writeInt32(bytes.length);
    writeBytes(bytes);
  }
}
