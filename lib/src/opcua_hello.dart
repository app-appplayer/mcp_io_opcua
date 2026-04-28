/// OPC UA Binary Hello / Acknowledge / Error message codec
/// (OPC UA Part 6 § 7.1.2).
///
/// These are the only wire-level messages implemented in the MVP; the rest of
/// the protocol (SecureChannel + Session + Read/Write service sets) is
/// abstracted behind `OpcUaSession`.
///
/// Wire layout (all little-endian):
///   offset 0..2  : message type ("HEL" | "ACK" | "ERR")
///   offset 3     : chunk type ('F' = final)
///   offset 4..7  : total message size (uint32, including the 8-byte header)
///   offset 8..   : message body (format differs per type)
///
/// Hello body:
///   protocolVersion   u32
///   receiveBufferSize u32
///   sendBufferSize    u32
///   maxMessageSize    u32
///   maxChunkCount     u32
///   endpointUrl       OPC UA string (i32 length + UTF-8 bytes, -1 = null)
///
/// Acknowledge body:
///   protocolVersion   u32
///   receiveBufferSize u32
///   sendBufferSize    u32
///   maxMessageSize    u32
///   maxChunkCount     u32
///
/// Error body:
///   error             u32 (OPC UA status code)
///   reason            OPC UA string
library;

import 'dart:convert';
import 'dart:typed_data';

import 'opcua_types.dart';

class OpcUaHelloMessage {
  final int protocolVersion;
  final int receiveBufferSize;
  final int sendBufferSize;
  final int maxMessageSize;
  final int maxChunkCount;
  final String endpointUrl;

  const OpcUaHelloMessage({
    this.protocolVersion = 0,
    required this.receiveBufferSize,
    required this.sendBufferSize,
    required this.maxMessageSize,
    required this.maxChunkCount,
    required this.endpointUrl,
  });

  Uint8List encode() {
    final urlBytes = utf8.encode(endpointUrl);
    final body = ByteData(20 + 4 + urlBytes.length)
      ..setUint32(0, protocolVersion, Endian.little)
      ..setUint32(4, receiveBufferSize, Endian.little)
      ..setUint32(8, sendBufferSize, Endian.little)
      ..setUint32(12, maxMessageSize, Endian.little)
      ..setUint32(16, maxChunkCount, Endian.little)
      ..setInt32(20, urlBytes.length, Endian.little);
    final bodyBytes = body.buffer.asUint8List();
    for (var i = 0; i < urlBytes.length; i++) {
      bodyBytes[24 + i] = urlBytes[i];
    }
    return _wrap('HEL', bodyBytes);
  }

  factory OpcUaHelloMessage.decode(List<int> frame) {
    final body = _unwrap('HEL', frame);
    final view = ByteData.sublistView(Uint8List.fromList(body));
    final urlLen = view.getInt32(20, Endian.little);
    if (urlLen < 0) {
      throw const OpcUaProtocolError('HEL: null endpoint URL not allowed');
    }
    if (body.length < 24 + urlLen) {
      throw const OpcUaProtocolError('HEL: truncated endpoint URL');
    }
    final url = utf8.decode(body.sublist(24, 24 + urlLen));
    return OpcUaHelloMessage(
      protocolVersion: view.getUint32(0, Endian.little),
      receiveBufferSize: view.getUint32(4, Endian.little),
      sendBufferSize: view.getUint32(8, Endian.little),
      maxMessageSize: view.getUint32(12, Endian.little),
      maxChunkCount: view.getUint32(16, Endian.little),
      endpointUrl: url,
    );
  }
}

class OpcUaAcknowledgeMessage {
  final int protocolVersion;
  final int receiveBufferSize;
  final int sendBufferSize;
  final int maxMessageSize;
  final int maxChunkCount;

  const OpcUaAcknowledgeMessage({
    this.protocolVersion = 0,
    required this.receiveBufferSize,
    required this.sendBufferSize,
    required this.maxMessageSize,
    required this.maxChunkCount,
  });

  Uint8List encode() {
    final body = ByteData(20)
      ..setUint32(0, protocolVersion, Endian.little)
      ..setUint32(4, receiveBufferSize, Endian.little)
      ..setUint32(8, sendBufferSize, Endian.little)
      ..setUint32(12, maxMessageSize, Endian.little)
      ..setUint32(16, maxChunkCount, Endian.little);
    return _wrap('ACK', body.buffer.asUint8List());
  }

  factory OpcUaAcknowledgeMessage.decode(List<int> frame) {
    final body = _unwrap('ACK', frame);
    if (body.length < 20) {
      throw const OpcUaProtocolError('ACK: body too short');
    }
    final view = ByteData.sublistView(Uint8List.fromList(body));
    return OpcUaAcknowledgeMessage(
      protocolVersion: view.getUint32(0, Endian.little),
      receiveBufferSize: view.getUint32(4, Endian.little),
      sendBufferSize: view.getUint32(8, Endian.little),
      maxMessageSize: view.getUint32(12, Endian.little),
      maxChunkCount: view.getUint32(16, Endian.little),
    );
  }
}

class OpcUaErrorMessage {
  /// OPC UA status code (OPC UA Part 4 Table A.2).
  final int errorCode;
  final String reason;

  const OpcUaErrorMessage({required this.errorCode, required this.reason});

  Uint8List encode() {
    final reasonBytes = utf8.encode(reason);
    final body = ByteData(4 + 4 + reasonBytes.length)
      ..setUint32(0, errorCode, Endian.little)
      ..setInt32(4, reasonBytes.length, Endian.little);
    final bodyBytes = body.buffer.asUint8List();
    for (var i = 0; i < reasonBytes.length; i++) {
      bodyBytes[8 + i] = reasonBytes[i];
    }
    return _wrap('ERR', bodyBytes);
  }

  factory OpcUaErrorMessage.decode(List<int> frame) {
    final body = _unwrap('ERR', frame);
    final view = ByteData.sublistView(Uint8List.fromList(body));
    final reasonLen = view.getInt32(4, Endian.little);
    if (reasonLen < 0) {
      return OpcUaErrorMessage(
        errorCode: view.getUint32(0, Endian.little), reason: '',
      );
    }
    if (body.length < 8 + reasonLen) {
      throw const OpcUaProtocolError('ERR: truncated reason');
    }
    return OpcUaErrorMessage(
      errorCode: view.getUint32(0, Endian.little),
      reason: utf8.decode(body.sublist(8, 8 + reasonLen)),
    );
  }
}

/// Build the 8-byte header followed by [body]. Chunk type is always 'F'
/// (final) for Hello/Acknowledge/Error — they are never chunked.
Uint8List _wrap(String type, Uint8List body) {
  if (type.length != 3) {
    throw OpcUaProtocolError('invalid message type: $type');
  }
  final total = 8 + body.length;
  final bytes = Uint8List(total);
  bytes[0] = type.codeUnitAt(0);
  bytes[1] = type.codeUnitAt(1);
  bytes[2] = type.codeUnitAt(2);
  bytes[3] = 'F'.codeUnitAt(0);
  final header = ByteData.sublistView(bytes)..setUint32(4, total, Endian.little);
  // header writes into the shared bytes buffer; use the view explicitly.
  header.setUint32(4, total, Endian.little);
  for (var i = 0; i < body.length; i++) {
    bytes[8 + i] = body[i];
  }
  return bytes;
}

List<int> _unwrap(String expected, List<int> frame) {
  if (frame.length < 8) {
    throw const OpcUaProtocolError('frame too short');
  }
  final type = String.fromCharCodes(frame.sublist(0, 3));
  if (type != expected) {
    throw OpcUaProtocolError('expected $expected, got $type');
  }
  final chunkType = String.fromCharCode(frame[3]);
  if (chunkType != 'F') {
    throw OpcUaProtocolError('unsupported chunk type: $chunkType');
  }
  final view = ByteData.sublistView(Uint8List.fromList(frame));
  final total = view.getUint32(4, Endian.little);
  if (frame.length != total) {
    throw OpcUaProtocolError(
      'frame size mismatch — declared $total, got ${frame.length}',
    );
  }
  return frame.sublist(8);
}
