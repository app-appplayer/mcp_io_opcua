import 'package:mcp_bundle/mcp_bundle.dart';
import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:test/test.dart';

OpcUaAdapter _adapter(InMemoryOpcUaSession session) => OpcUaAdapter(
      deviceId: 'plc-01',
      endpoint: Uri.parse('opc.tcp://127.0.0.1:4840'),
      session: session,
    );

void main() {
  group('connect / disconnect', () {
    test('connect opens the session', () async {
      final session = InMemoryOpcUaSession();
      final adapter = _adapter(session);
      await adapter.connect();
      expect(session.isOpen, isTrue);
      expect((await adapter.describe()).connectionState,
        IoConnectionState.connected);
    });

    test('disconnect closes the session', () async {
      final session = InMemoryOpcUaSession();
      final adapter = _adapter(session);
      await adapter.connect();
      await adapter.disconnect();
      expect(session.isClosed, isTrue);
      expect((await adapter.describe()).connectionState,
        IoConnectionState.disconnected);
    });
  });

  group('read', () {
    test('single target returns scalar envelope', () async {
      final session = InMemoryOpcUaSession()
        ..seed(
          const OpcUaNodeId.numeric(namespace: 2, identifier: 1001),
          const OpcUaVariant.double(21.5),
        );
      final adapter = _adapter(session);
      await adapter.connect();
      final res = await adapter.read(
        const ReadSpec(targets: ['ns=2;i=1001']),
      );
      final item = res.items.single;
      expect(item.error, isNull);
      expect(item.envelope?.payload.type, PayloadType.scalar);
      expect(item.envelope?.payload.value, 21.5);
    });

    test('missing node returns null payload (no error)', () async {
      final session = InMemoryOpcUaSession();
      final adapter = _adapter(session);
      await adapter.connect();
      final res = await adapter.read(
        const ReadSpec(targets: ['ns=2;i=9999']),
      );
      final item = res.items.single;
      expect(item.error, isNull);
      expect(item.envelope?.payload.type, PayloadType.null_);
      expect(item.envelope?.payload.value, isNull);
    });

    test('invalid NodeId string → per-target IoError', () async {
      final session = InMemoryOpcUaSession();
      final adapter = _adapter(session);
      await adapter.connect();
      final res = await adapter.read(
        const ReadSpec(targets: ['not-a-nodeid']),
      );
      expect(res.items.single.envelope, isNull);
      expect(res.items.single.error, isNotNull);
    });

    test('multiple targets — error isolation', () async {
      final session = InMemoryOpcUaSession()
        ..seed(
          const OpcUaNodeId.numeric(namespace: 0, identifier: 7),
          const OpcUaVariant.int32(42),
        );
      final adapter = _adapter(session);
      await adapter.connect();
      final res = await adapter.read(
        const ReadSpec(targets: ['i=7', 'broken']),
      );
      expect(res.items[0].envelope?.payload.value, 42);
      expect(res.items[1].error, isNotNull);
    });

    test('session not open → error propagated per target', () async {
      final session = InMemoryOpcUaSession();
      final adapter = _adapter(session);
      // Note: not connected.
      final res = await adapter.read(const ReadSpec(targets: ['i=1']));
      expect(res.items.single.error, isNotNull);
    });
  });

  group('execute — write', () {
    test('writes value through session and reports completed', () async {
      final session = InMemoryOpcUaSession();
      final adapter = _adapter(session);
      await adapter.connect();
      final res = await adapter.execute(const Command(
        action: 'write', target: 'ns=2;i=1001',
        args: {'value': 22.0},
      ));
      expect(res.status, CommandStatus.completed);
      final snap = session.snapshot();
      expect(
        snap[const OpcUaNodeId.numeric(namespace: 2, identifier: 1001)]!.value,
        22.0,
      );
    });

    test('string value writes as string variant', () async {
      final session = InMemoryOpcUaSession();
      final adapter = _adapter(session);
      await adapter.connect();
      await adapter.execute(const Command(
        action: 'write', target: 'ns=2;s=Label',
        args: {'value': 'hello'},
      ));
      final v = session.snapshot()[
        const OpcUaNodeId.string(namespace: 2, identifier: 'Label')
      ]!;
      expect(v.kind, OpcUaVariantKind.string);
      expect(v.value, 'hello');
    });

    test('args.namespace + numeric override the target', () async {
      final session = InMemoryOpcUaSession();
      final adapter = _adapter(session);
      await adapter.connect();
      await adapter.execute(const Command(
        action: 'write', target: 'ignored',
        args: {'namespace': 5, 'numeric': 99, 'value': 1},
      ));
      final v = session.snapshot()[
        const OpcUaNodeId.numeric(namespace: 5, identifier: 99)
      ]!;
      expect(v.value, 1);
    });

    test('missing value → rejected', () async {
      final session = InMemoryOpcUaSession();
      final adapter = _adapter(session);
      await adapter.connect();
      final res = await adapter.execute(const Command(
        action: 'write', target: 'i=1',
      ));
      expect(res.status, CommandStatus.rejected);
      expect(res.error?.code, 'exec.invalid_args');
    });

    test('unknown action → rejected', () async {
      final session = InMemoryOpcUaSession();
      final adapter = _adapter(session);
      await adapter.connect();
      final res = await adapter.execute(const Command(
        action: 'nope', target: 'i=1',
      ));
      expect(res.status, CommandStatus.rejected);
    });

    test('invalid NodeId → failed', () async {
      final session = InMemoryOpcUaSession();
      final adapter = _adapter(session);
      await adapter.connect();
      final res = await adapter.execute(const Command(
        action: 'write', target: 'not-a-node',
        args: {'value': 1},
      ));
      expect(res.status, CommandStatus.failed);
    });
  });

  group('subscribe (polling)', () {
    test('emits the value on listen + each interval tick', () async {
      final session = InMemoryOpcUaSession()
        ..seed(
          const OpcUaNodeId.numeric(namespace: 0, identifier: 1),
          const OpcUaVariant.int32(10),
        );
      final adapter = _adapter(session);
      await adapter.connect();
      final received = <int>[];
      final sub = adapter.subscribe(const TopicSpec(
        uri: 'i=1', mode: TopicMode.poll,
        options: TopicOptions(intervalMs: 30),
      )).listen((env) => received.add(env.payload.value as int));
      await Future<void>.delayed(const Duration(milliseconds: 100));
      await sub.cancel();
      expect(received, isNotEmpty);
      expect(received.first, 10);
      expect(session.readCount, greaterThanOrEqualTo(2));
    });

    test('cancel stops the polling timer', () async {
      final session = InMemoryOpcUaSession()
        ..seed(
          const OpcUaNodeId.numeric(namespace: 0, identifier: 1),
          const OpcUaVariant.int32(1),
        );
      final adapter = _adapter(session);
      await adapter.connect();
      final sub = adapter.subscribe(const TopicSpec(
        uri: 'i=1', mode: TopicMode.poll,
        options: TopicOptions(intervalMs: 20),
      )).listen((_) {});
      await Future<void>.delayed(const Duration(milliseconds: 60));
      final snapshot = session.readCount;
      await sub.cancel();
      await Future<void>.delayed(const Duration(milliseconds: 80));
      expect(session.readCount, snapshot);
    });

    test('invalid NodeId emits stream error', () async {
      final session = InMemoryOpcUaSession();
      final adapter = _adapter(session);
      await adapter.connect();
      final errors = <Object>[];
      final sub = adapter.subscribe(const TopicSpec(
        uri: 'bad', mode: TopicMode.poll,
        options: TopicOptions(intervalMs: 20),
      )).listen((_) {}, onError: errors.add);
      await Future<void>.delayed(const Duration(milliseconds: 40));
      await sub.cancel();
      expect(errors, isNotEmpty);
    });
  });

  group('lifecycle + emergency', () {
    test('emergencyStop disconnects and reports success', () async {
      final session = InMemoryOpcUaSession();
      final adapter = _adapter(session);
      await adapter.connect();
      final r = await adapter.emergencyStop(const EmergencyStopRequest(
        reason: 't', actorId: 'u',
      ));
      expect(r.success, isTrue);
      expect(session.isClosed, isTrue);
    });

    test('probe returns empty list (no broadcast discovery)', () async {
      final adapter = _adapter(InMemoryOpcUaSession());
      expect(await adapter.probe(null), isEmpty);
    });

    test('describe exposes endpoint host as model', () async {
      final adapter = _adapter(InMemoryOpcUaSession());
      final d = await adapter.describe();
      expect(d.model, '127.0.0.1');
      expect(d.transport, 'opc.tcp');
    });
  });
}
