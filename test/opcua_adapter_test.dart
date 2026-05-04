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

  group('capability dispatch (0.2.0)', () {
    test('opcua.read returns the seeded scalar value', () async {
      final session = InMemoryOpcUaSession();
      session.seed(
        OpcUaNodeId.numeric(namespace: 2, identifier: 1001),
        const OpcUaVariant.double(42.0),
      );
      final adapter = _adapter(session);
      await adapter.connect();
      final r = await adapter.execute(const Command(
        action: 'opcua.read', target: 'ns=2;i=1001',
      ));
      expect(r.status, CommandStatus.completed);
      expect(r.result?['value'], 42.0);
      expect(r.result?['kind'], 'double');
    });

    test('opcua.write routes through the session and updates the store',
        () async {
      final session = InMemoryOpcUaSession();
      final adapter = _adapter(session);
      await adapter.connect();
      final r = await adapter.execute(const Command(
        action: 'opcua.write', target: 'ns=2;s=Setpoint',
        args: {'value': 7},
      ));
      expect(r.status, CommandStatus.completed);
      expect(session.writeCount, 1);
      final after = session.snapshot();
      expect(
        after[OpcUaNodeId.string(namespace: 2, identifier: 'Setpoint')]?.value,
        7,
      );
    });

    test('opcua.browse returns seeded references with maxResults respected',
        () async {
      final from = OpcUaNodeId.numeric(namespace: 0, identifier: 84);
      final session = InMemoryOpcUaSession();
      session.seedReferences(from, [
        OpcUaReferenceDescription(
          targetNodeId: OpcUaNodeId.numeric(namespace: 0, identifier: 85),
          browseName: '0:Objects',
          displayName: 'Objects',
        ),
        OpcUaReferenceDescription(
          targetNodeId: OpcUaNodeId.numeric(namespace: 0, identifier: 86),
          browseName: '0:Types',
          displayName: 'Types',
        ),
      ]);
      final adapter = _adapter(session);
      await adapter.connect();
      final r = await adapter.execute(const Command(
        action: 'opcua.browse', target: 'ns=0;i=84',
        args: {'maxResults': 1},
      ));
      expect(r.status, CommandStatus.completed);
      expect((r.result!['references'] as List), hasLength(1));
      expect((r.result!['references'] as List).first['browseName'], '0:Objects');
    });

    test('opcua.call_method invokes the registered handler', () async {
      final obj = OpcUaNodeId.numeric(namespace: 2, identifier: 1);
      final mth = OpcUaNodeId.numeric(namespace: 2, identifier: 2);
      final session = InMemoryOpcUaSession();
      session.registerMethod(obj, mth, (inputs) {
        final a = inputs[0].value as int;
        final b = inputs[1].value as int;
        return OpcUaCallResult(
          outputArguments: [OpcUaVariant.int32(a + b)],
        );
      });
      final adapter = _adapter(session);
      await adapter.connect();
      final r = await adapter.execute(const Command(
        action: 'opcua.call_method', target: '',
        args: {
          'object': 'ns=2;i=1',
          'method': 'ns=2;i=2',
          'inputs': [3, 4],
        },
      ));
      expect(r.status, CommandStatus.completed);
      expect(r.result?['outputs'], [7]);
    });

    test('opcua.call_method reports failed status code', () async {
      final session = InMemoryOpcUaSession();
      final adapter = _adapter(session);
      await adapter.connect();
      final r = await adapter.execute(const Command(
        action: 'opcua.call_method', target: '',
        args: {'object': 'ns=2;i=1', 'method': 'ns=2;i=99'},
      ));
      expect(r.status, CommandStatus.failed);
      expect(r.error?.code, 'protocol.method_failed');
    });

    test('opcua.history_read returns points within the window', () async {
      final node = OpcUaNodeId.numeric(namespace: 2, identifier: 10);
      final session = InMemoryOpcUaSession();
      final t0 = DateTime.utc(2026, 5, 2, 12, 0, 0);
      for (var i = 0; i < 5; i++) {
        session.seedHistory(node, OpcUaHistoryDataPoint(
          value: OpcUaVariant.double(i.toDouble()),
          sourceTimestamp: t0.add(Duration(minutes: i)),
        ));
      }
      final adapter = _adapter(session);
      await adapter.connect();
      final r = await adapter.execute(Command(
        action: 'opcua.history_read', target: 'ns=2;i=10',
        args: {
          'from': t0.add(const Duration(minutes: 1)).toIso8601String(),
          'to': t0.add(const Duration(minutes: 3)).toIso8601String(),
        },
      ));
      expect(r.status, CommandStatus.completed);
      expect(r.result?['count'], 3);
    });

    test('opcua.subscribe_data + subscribe_event ack a parseable NodeId',
        () async {
      final session = InMemoryOpcUaSession();
      final adapter = _adapter(session);
      await adapter.connect();
      final d = await adapter.execute(const Command(
        action: 'opcua.subscribe_data', target: 'ns=2;i=10',
      ));
      final e = await adapter.execute(const Command(
        action: 'opcua.subscribe_event', target: 'ns=0;i=2253',
      ));
      expect(d.status, CommandStatus.completed);
      expect(e.status, CommandStatus.completed);
    });

    test('opcua.write rejects when value missing', () async {
      final session = InMemoryOpcUaSession();
      final adapter = _adapter(session);
      await adapter.connect();
      final r = await adapter.execute(const Command(
        action: 'opcua.write', target: 'ns=2;i=1',
      ));
      expect(r.status, CommandStatus.rejected);
      expect(r.error?.code, 'exec.invalid_args');
    });

    test('opcua.history_read rejects when window missing', () async {
      final session = InMemoryOpcUaSession();
      final adapter = _adapter(session);
      await adapter.connect();
      final r = await adapter.execute(const Command(
        action: 'opcua.history_read', target: 'ns=2;i=10',
      ));
      expect(r.status, CommandStatus.rejected);
      expect(r.error?.code, 'exec.invalid_args');
    });
  });
}
