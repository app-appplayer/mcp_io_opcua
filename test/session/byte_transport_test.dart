import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:test/test.dart';

void main() {
  group('InMemoryOpcUaByteTransport', () {
    test('TC-BT-001 paired transports deliver bytes to each other', () async {
      final a = InMemoryOpcUaByteTransport();
      final b = InMemoryOpcUaByteTransport();
      a.pairWith(b);
      await a.open();
      await b.open();

      final fromB = <List<int>>[];
      final sub = b.incoming.listen(fromB.add);
      await a.send([1, 2, 3]);
      // Allow the broadcast stream to dispatch.
      await Future<void>.delayed(Duration.zero);
      expect(fromB, [
        [1, 2, 3]
      ]);
      await sub.cancel();
      await a.close();
      await b.close();
    });

    test('TC-BT-002 inject pushes onto the local incoming stream', () async {
      final t = InMemoryOpcUaByteTransport();
      final received = <List<int>>[];
      final sub = t.incoming.listen(received.add);
      t.inject([0x10, 0x20]);
      await Future<void>.delayed(Duration.zero);
      expect(received, [
        [0x10, 0x20]
      ]);
      await sub.cancel();
    });

    test('TC-BT-003 send after close throws', () async {
      final t = InMemoryOpcUaByteTransport();
      await t.open();
      await t.close();
      expect(() => t.send([0]), throwsStateError);
    });

    test('TC-BT-004 recorded sent buffer matches outgoing chunks', () async {
      final t = InMemoryOpcUaByteTransport();
      await t.open();
      await t.send([0xAA]);
      await t.send([0xBB, 0xCC]);
      expect(t.sent.map((b) => b.toList()), [
        [0xAA],
        [0xBB, 0xCC],
      ]);
    });
  });
}
