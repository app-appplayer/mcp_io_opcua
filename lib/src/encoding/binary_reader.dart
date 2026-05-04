import 'dart:typed_data';

/// Little-endian binary reader over a byte buffer.
///
/// OPC UA Binary uses little-endian for all multi-byte numeric values
/// (Part 6 §5.1.5).
class BinaryReader {
  factory BinaryReader(List<int> bytes) {
    final buf = bytes is Uint8List ? bytes : Uint8List.fromList(bytes);
    return BinaryReader._(buf, ByteData.sublistView(buf));
  }

  BinaryReader._(this._bytes, this._view);

  final Uint8List _bytes;
  final ByteData _view;
  int _offset = 0;

  int get offset => _offset;
  int get length => _bytes.length;
  int get remaining => _bytes.length - _offset;

  void seek(int offset) {
    if (offset < 0 || offset > _bytes.length) {
      throw RangeError.range(offset, 0, _bytes.length, 'offset');
    }
    _offset = offset;
  }

  void _ensure(int n) {
    if (_offset + n > _bytes.length) {
      throw RangeError(
          'BinaryReader: out of bounds (need $n at $_offset, length ${_bytes.length})');
    }
  }

  int readUint8() {
    _ensure(1);
    final v = _view.getUint8(_offset);
    _offset += 1;
    return v;
  }

  int readInt8() {
    _ensure(1);
    final v = _view.getInt8(_offset);
    _offset += 1;
    return v;
  }

  int readUint16() {
    _ensure(2);
    final v = _view.getUint16(_offset, Endian.little);
    _offset += 2;
    return v;
  }

  int readInt16() {
    _ensure(2);
    final v = _view.getInt16(_offset, Endian.little);
    _offset += 2;
    return v;
  }

  int readUint32() {
    _ensure(4);
    final v = _view.getUint32(_offset, Endian.little);
    _offset += 4;
    return v;
  }

  int readInt32() {
    _ensure(4);
    final v = _view.getInt32(_offset, Endian.little);
    _offset += 4;
    return v;
  }

  int readUint64() {
    _ensure(8);
    final v = _view.getUint64(_offset, Endian.little);
    _offset += 8;
    return v;
  }

  int readInt64() {
    _ensure(8);
    final v = _view.getInt64(_offset, Endian.little);
    _offset += 8;
    return v;
  }

  double readFloat32() {
    _ensure(4);
    final v = _view.getFloat32(_offset, Endian.little);
    _offset += 4;
    return v;
  }

  double readFloat64() {
    _ensure(8);
    final v = _view.getFloat64(_offset, Endian.little);
    _offset += 8;
    return v;
  }

  Uint8List readBytes(int n) {
    _ensure(n);
    final out = Uint8List.fromList(_bytes.sublist(_offset, _offset + n));
    _offset += n;
    return out;
  }

  /// Read an OPC UA String / ByteString / XmlElement (length-prefixed
  /// int32 LE; -1 = null).
  Uint8List? readByteStringOrNull() {
    final len = readInt32();
    if (len < 0) return null;
    return readBytes(len);
  }

  String? readStringOrNull() {
    final raw = readByteStringOrNull();
    if (raw == null) return null;
    return String.fromCharCodes(raw); // UTF-8 decoder applied at higher layer
  }
}
