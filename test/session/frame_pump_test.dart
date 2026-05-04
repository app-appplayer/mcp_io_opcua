import 'dart:async';
import 'dart:typed_data';

import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:test/test.dart';

/// Build a minimal OPC UA frame: 8-byte transport header + body.
Uint8List _hel({String type = 'HEL', String chunk = 'F', int bodyLen = 4}) {
  final total = 8 + bodyLen;
  final bytes = Uint8List(total);
  bytes[0] = type.codeUnitAt(0);
  bytes[1] = type.codeUnitAt(1);
  bytes[2] = type.codeUnitAt(2);
  bytes[3] = chunk.codeUnitAt(0);
  ByteData.sublistView(bytes).setUint32(4, total, Endian.little);
  for (var i = 0; i < bodyLen; i++) {
    bytes[8 + i] = i & 0xFF;
  }
  return bytes;
}

void main() {
  group('OpcUaFramePump', () {
    test('TC-FP-001 emits one frame on a single full chunk', () async {
      final pump = OpcUaFramePump();
      final frames = <OpcUaWireFrame>[];
      final sub = pump.frames.listen(frames.add);
      pump.feed(_hel());
      await Future<void>.delayed(Duration.zero);
      expect(frames, hasLength(1));
      expect(frames[0].messageType, 'HEL');
      expect(frames[0].chunkType, 'F');
      expect(frames[0].bytes.length, 12);
      expect(pump.bufferedBytes, 0);
      await sub.cancel();
    });

    test('TC-FP-002 reassembles frame split across two chunks', () async {
      final pump = OpcUaFramePump();
      final frames = <OpcUaWireFrame>[];
      final sub = pump.frames.listen(frames.add);
      final whole = _hel(bodyLen: 16);
      pump.feed(whole.sublist(0, 5));
      await Future<void>.delayed(Duration.zero);
      expect(frames, isEmpty);
      expect(pump.bufferedBytes, 5);
      pump.feed(whole.sublist(5));
      await Future<void>.delayed(Duration.zero);
      expect(frames, hasLength(1));
      expect(frames[0].bytes, whole);
      expect(pump.bufferedBytes, 0);
      await sub.cancel();
    });

    test('TC-FP-003 emits two back-to-back frames in one chunk', () async {
      final pump = OpcUaFramePump();
      final frames = <OpcUaWireFrame>[];
      final sub = pump.frames.listen(frames.add);
      final a = _hel(type: 'ACK', bodyLen: 4);
      final b = _hel(type: 'OPN', bodyLen: 8);
      final combined = Uint8List(a.length + b.length)
        ..setAll(0, a)
        ..setAll(a.length, b);
      pump.feed(combined);
      await Future<void>.delayed(Duration.zero);
      expect(frames, hasLength(2));
      expect(frames[0].messageType, 'ACK');
      expect(frames[1].messageType, 'OPN');
      expect(pump.bufferedBytes, 0);
      await sub.cancel();
    });

    test('TC-FP-004 unknown message type raises protocol error', () async {
      final pump = OpcUaFramePump();
      final errors = <Object>[];
      final sub = pump.frames.listen((_) {}, onError: errors.add);
      try {
        pump.feed(Uint8List.fromList(
            [0x58, 0x59, 0x5A, 0x46, 12, 0, 0, 0, 0, 0, 0, 0]));
        fail('expected throw');
      } on OpcUaProtocolError {
        // ok
      }
      await sub.cancel();
      expect(errors, isEmpty);
    });

    test('TC-FP-005 frame size exceeding maxFrameSize throws', () async {
      final pump = OpcUaFramePump(maxFrameSize: 32);
      // Declare a 1024-byte frame.
      final bytes = Uint8List(8);
      bytes[0] = 'M'.codeUnitAt(0);
      bytes[1] = 'S'.codeUnitAt(0);
      bytes[2] = 'G'.codeUnitAt(0);
      bytes[3] = 'F'.codeUnitAt(0);
      ByteData.sublistView(bytes).setUint32(4, 1024, Endian.little);
      expect(() => pump.feed(bytes), throwsA(isA<OpcUaProtocolError>()));
    });

    test('TC-FP-006 bind drains an upstream stream', () async {
      final pump = OpcUaFramePump();
      final ctrl = StreamController<List<int>>();
      final frames = <OpcUaWireFrame>[];
      final framesSub = pump.frames.listen(frames.add);
      pump.bind(ctrl.stream);
      ctrl.add(_hel());
      ctrl.add(_hel(type: 'MSG', bodyLen: 12));
      await Future<void>.delayed(Duration.zero);
      expect(frames, hasLength(2));
      expect(frames[0].messageType, 'HEL');
      expect(frames[1].messageType, 'MSG');
      await framesSub.cancel();
      await ctrl.close();
    });
  });
}
