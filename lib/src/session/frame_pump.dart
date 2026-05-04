/// Reassembles a stream of arbitrary byte chunks into a stream of complete
/// OPC UA wire frames.
///
/// OPC UA Binary always prefaces every message with a fixed 8-byte header
/// (transport-level — `HEL`/`ACK`/`ERR`) or 12-byte header
/// (`OPN`/`CLO`/`MSG`). The first 4 bytes (`message-type[3] + chunk[1]`)
/// classify the frame; offset 4..7 carries `messageSize` (uint32 LE)
/// covering the whole frame including the header.
///
/// Production sockets emit chunks at arbitrary boundaries — the consumer
/// must accumulate until `messageSize` bytes have arrived, then hand the
/// buffer to a decoder. This pump performs that accumulation and emits
/// one event per complete frame.
///
/// The decoded frame type is left to the caller — the pump only checks
/// the message-type tag for sanity (3 ASCII bytes) and the size field
/// for non-zero/length-cap.
library;

import 'dart:async';
import 'dart:typed_data';

import '../opcua_types.dart';

/// One framed message ready for further decoding.
class OpcUaWireFrame {
  /// 3-letter message type (`HEL`, `ACK`, `ERR`, `OPN`, `CLO`, `MSG`).
  final String messageType;

  /// 1-byte chunk type (`F`, `C`, `A`).
  final String chunkType;

  /// Complete frame bytes (header + body). The byte at index 0 is the
  /// first character of [messageType].
  final Uint8List bytes;

  const OpcUaWireFrame({
    required this.messageType,
    required this.chunkType,
    required this.bytes,
  });
}

/// Buffered byte accumulator that emits [OpcUaWireFrame] events.
class OpcUaFramePump {
  /// Hard upper bound on a single frame size — any [messageSize] field
  /// larger than this throws [OpcUaProtocolError]. Defaults to 16 MiB
  /// which exceeds any reasonable OPC UA hand-shake or service
  /// payload.
  final int maxFrameSize;

  OpcUaFramePump({this.maxFrameSize = 16 * 1024 * 1024});

  Uint8List _buffer = Uint8List(0);

  // ignore: close_sinks
  final StreamController<OpcUaWireFrame> _ctrl =
      StreamController<OpcUaWireFrame>.broadcast();

  Stream<OpcUaWireFrame> get frames => _ctrl.stream;

  /// Total buffered bytes that have not yet formed a complete frame.
  int get bufferedBytes => _buffer.length;

  /// Feed raw bytes into the pump. Emits zero or more [OpcUaWireFrame]
  /// events on [frames] before returning.
  void feed(List<int> chunk) {
    if (chunk.isEmpty) return;
    if (_buffer.isEmpty) {
      _buffer = Uint8List.fromList(chunk);
    } else {
      final next = Uint8List(_buffer.length + chunk.length);
      next.setAll(0, _buffer);
      next.setAll(_buffer.length, chunk);
      _buffer = next;
    }
    _drain();
  }

  void _drain() {
    while (_buffer.length >= 8) {
      // Header layout shared by all OPC UA Binary frames:
      //   [0..2]  messageType (3 ASCII bytes)
      //   [3]     chunkType   (1 ASCII byte)
      //   [4..7]  messageSize (uint32 LE)
      final type = String.fromCharCodes(_buffer.sublist(0, 3));
      _validateMessageType(type);
      final chunk = String.fromCharCode(_buffer[3]);
      _validateChunkType(chunk);
      final view = ByteData.sublistView(_buffer);
      final size = view.getUint32(4, Endian.little);
      if (size < 8 || size > maxFrameSize) {
        throw OpcUaProtocolError(
          'frame size out of range — declared $size '
          '(max ${maxFrameSize}B)',
        );
      }
      if (_buffer.length < size) {
        // Need more bytes; keep accumulating.
        return;
      }
      final frameBytes = Uint8List.fromList(_buffer.sublist(0, size));
      // Trim consumed bytes from the head of the buffer.
      _buffer = Uint8List.fromList(_buffer.sublist(size));
      if (!_ctrl.isClosed) {
        _ctrl.add(OpcUaWireFrame(
          messageType: type,
          chunkType: chunk,
          bytes: frameBytes,
        ));
      }
    }
  }

  /// Bind the pump to an upstream byte stream (e.g. a socket
  /// `Stream<Uint8List>`). Errors are forwarded; the upstream's `done`
  /// closes the pump.
  StreamSubscription<List<int>> bind(Stream<List<int>> source) {
    return source.listen(
      feed,
      onError: (Object e, StackTrace st) {
        if (!_ctrl.isClosed) _ctrl.addError(e, st);
      },
      onDone: close,
    );
  }

  Future<void> close() async {
    if (!_ctrl.isClosed) await _ctrl.close();
  }

  static const _validTypes = {'HEL', 'ACK', 'ERR', 'OPN', 'CLO', 'MSG', 'RHE'};
  static const _validChunks = {'F', 'C', 'A'};

  static void _validateMessageType(String type) {
    if (!_validTypes.contains(type)) {
      throw OpcUaProtocolError('unknown message type: "$type"');
    }
  }

  static void _validateChunkType(String chunk) {
    if (!_validChunks.contains(chunk)) {
      throw OpcUaProtocolError('unknown chunk type: "$chunk"');
    }
  }
}
