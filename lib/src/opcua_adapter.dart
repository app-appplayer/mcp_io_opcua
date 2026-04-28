/// OpcUaAdapter — `AdapterBase` implementation backed by an
/// [OpcUaSession].
///
/// URI convention: the standard OPC UA string form is used as the target,
/// e.g. `ns=2;i=1001` or `ns=3;s=Temp.Livingroom`. A `UriMapper` (not built
/// in to this package) may be layered on top to translate business URIs
/// into OPC UA NodeIds.
///
/// Command actions:
///   - `write` (target=NodeId string, args={value: Object,
///             namespace?: int, numeric?: int, string?: String}) —
///     writes the node value. When `args['namespace']` etc. are provided
///     they override whatever is parsed from `target`, which is convenient
///     when callers want to compose a NodeId in pieces.
///
/// Subscribe polls `session.read` at the interval supplied by
/// `TopicSpec.options.intervalMs` (default 1000 ms). Native OPC UA
/// subscription services are a follow-up.
library;

import 'dart:async';

import 'package:mcp_bundle/mcp_bundle.dart';
import 'package:mcp_io/mcp_io.dart';

import 'opcua_session.dart';
import 'opcua_types.dart';

class OpcUaAdapter extends AdapterBase {
  final String deviceId;
  final Uri endpoint;
  final OpcUaSession _session;

  IoConnectionState _state = IoConnectionState.disconnected;

  OpcUaAdapter({
    required this.deviceId,
    required this.endpoint,
    required OpcUaSession session,
    AdapterManifest? manifest,
  })  : _session = session,
        super(manifest: manifest ?? _defaultManifest);

  static final AdapterManifest _defaultManifest = AdapterManifest(
    adapterId: 'mcp_io_opcua',
    adapterVersion: '0.1.0',
    contractVersionRange: '>=0.1.0 <1.0.0',
    displayName: 'OPC UA Binary Adapter',
    description: 'OPC UA Binary MVP adapter — read/write via OpcUaSession; '
        'polling subscribe.',
  );

  // === Lifecycle ===

  @override
  Future<void> connect() async {
    await _session.open();
    _state = IoConnectionState.connected;
  }

  @override
  Future<void> disconnect() async {
    await _session.close();
    _state = IoConnectionState.disconnected;
  }

  @override
  Future<List<DeviceDescriptor>> probe(dynamic transport) async => const [];

  // === 4-Primitive Contract ===

  @override
  Future<DeviceDescriptor> describe() async {
    return DeviceDescriptor(
      deviceId: deviceId,
      manufacturer: 'OPC UA',
      model: endpoint.host.isEmpty ? 'unknown' : endpoint.host,
      transport: 'opc.tcp',
      connectionState: _state,
    );
  }

  @override
  Future<ReadResult> read(ReadSpec spec) async {
    final items = <ReadResultItem>[];
    for (final target in spec.targets) {
      try {
        final nodeId = OpcUaNodeId.parse(target);
        final variant = await _session.read(nodeId);
        items.add(ReadResultItem(
          uri: target, envelope: _envelope(target, variant),
        ));
      } catch (e) {
        items.add(ReadResultItem(
          uri: target, error: AdapterBase.mapException(e),
        ));
      }
    }
    return ReadResult(items: items);
  }

  @override
  Future<CommandResult> execute(Command command) async {
    try {
      switch (command.action) {
        case 'write':
          final nodeId = _resolveNodeId(command);
          if (!command.args.containsKey('value')) {
            return CommandResult(
              status: CommandStatus.rejected,
              error: IoError(
                code: 'exec.invalid_args',
                message: 'write requires args["value"]',
                timestamp: DateTime.now(),
              ),
            );
          }
          final variant = OpcUaVariant.fromDart(command.args['value']);
          await _session.write(nodeId, variant);
          return CommandResult(
            status: CommandStatus.completed,
            result: {'nodeId': nodeId.toStandardString()},
          );
        default:
          return CommandResult(
            status: CommandStatus.rejected,
            error: IoError(
              code: 'exec.unknown_action',
              message: 'Unknown action: ${command.action}',
              timestamp: DateTime.now(),
            ),
          );
      }
    } catch (e) {
      return CommandResult(
        status: CommandStatus.failed,
        error: AdapterBase.mapException(e),
      );
    }
  }

  @override
  Stream<PayloadEnvelope> subscribe(TopicSpec spec) {
    final intervalMs = spec.options?.intervalMs ?? 1000;
    final interval = Duration(milliseconds: intervalMs);
    late StreamController<PayloadEnvelope> ctrl;
    Timer? timer;

    Future<void> poll() async {
      if (ctrl.isClosed) return;
      try {
        final nodeId = OpcUaNodeId.parse(spec.uri);
        final variant = await _session.read(nodeId);
        ctrl.add(_envelope(spec.uri, variant));
      } catch (e) {
        if (!ctrl.isClosed) ctrl.addError(e);
      }
    }

    ctrl = StreamController<PayloadEnvelope>.broadcast(
      onListen: () {
        poll();
        timer = Timer.periodic(interval, (_) => poll());
      },
      onCancel: () {
        timer?.cancel();
        timer = null;
      },
    );
    return ctrl.stream;
  }

  @override
  Future<EmergencyStopResult> emergencyStop(EmergencyStopRequest request) async {
    await disconnect();
    return EmergencyStopResult(success: true, stoppedDevices: [deviceId]);
  }

  // === Internal helpers ===

  OpcUaNodeId _resolveNodeId(Command command) {
    final namespace = command.args['namespace'] as int?;
    if (namespace != null) {
      final numeric = command.args['numeric'] as int?;
      if (numeric != null) {
        return OpcUaNodeId.numeric(namespace: namespace, identifier: numeric);
      }
      final stringId = command.args['string'] as String?;
      if (stringId != null) {
        return OpcUaNodeId.string(namespace: namespace, identifier: stringId);
      }
    }
    return OpcUaNodeId.parse(command.target);
  }

  PayloadEnvelope _envelope(String uri, OpcUaVariant variant) {
    final type = switch (variant.kind) {
      OpcUaVariantKind.bytes => PayloadType.blob,
      OpcUaVariantKind.string => PayloadType.scalar,
      OpcUaVariantKind.boolean => PayloadType.scalar,
      OpcUaVariantKind.int32 => PayloadType.scalar,
      OpcUaVariantKind.int64 => PayloadType.scalar,
      OpcUaVariantKind.double => PayloadType.scalar,
      OpcUaVariantKind.nullKind => PayloadType.null_,
    };
    return PayloadEnvelope(
      uri: uri,
      kind: PayloadKind.read,
      payload: TypedPayload(
        type: type,
        value: variant.value,
        timestamp: DateTime.now(),
      ),
      meta: EnvelopeMeta(
        capturedAt: DateTime.now(),
        sourceAddress: uri,
      ),
    );
  }
}
