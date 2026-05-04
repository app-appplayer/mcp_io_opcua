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
    adapterVersion: '0.2.0',
    contractVersionRange: '>=0.1.0 <1.0.0',
    displayName: 'OPC UA Binary Adapter',
    description:
        'OPC UA Binary adapter — Variant 25 built-in types, NodeId 5 encodings, '
        'DataValue mask, ExtensionObject, polling subscribe. Service set '
        '(Open/CloseSecureChannel, CreateSession/ActivateSession, Read/Write/'
        'Browse/CallMethod, Subscription/MonitoredItems/Publish) deferred to '
        'C-3b~f.',
    capabilities: const [
      CapabilityDescriptor(action: 'opcua.browse', safetyClass: SafetyClass.safe),
      CapabilityDescriptor(action: 'opcua.read', safetyClass: SafetyClass.safe),
      CapabilityDescriptor(action: 'opcua.write', safetyClass: SafetyClass.guarded),
      CapabilityDescriptor(action: 'opcua.call_method', safetyClass: SafetyClass.guarded),
      CapabilityDescriptor(action: 'opcua.subscribe_data', safetyClass: SafetyClass.safe),
      CapabilityDescriptor(action: 'opcua.subscribe_event', safetyClass: SafetyClass.safe),
      CapabilityDescriptor(action: 'opcua.history_read', safetyClass: SafetyClass.safe),
    ],
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
        // Legacy + canonical write.
        case 'write':
        case 'opcua.write':
          return await _doWrite(command);

        case 'opcua.read':
          return await _doRead(command);
        case 'opcua.browse':
          return await _doBrowse(command);
        case 'opcua.call_method':
          return await _doCallMethod(command);
        case 'opcua.history_read':
          return await _doHistoryRead(command);
        case 'opcua.subscribe_data':
        case 'opcua.subscribe_event':
          return _doSubscribeAck(command);

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

  // === Capability dispatch helpers ===

  Future<CommandResult> _doWrite(Command command) async {
    final nodeId = _resolveNodeId(command);
    if (!command.args.containsKey('value')) {
      return _argError('write requires args["value"]');
    }
    final variant = OpcUaVariant.fromDart(command.args['value']);
    await _session.write(nodeId, variant);
    return CommandResult(
      status: CommandStatus.completed,
      result: {'nodeId': nodeId.toStandardString()},
    );
  }

  Future<CommandResult> _doRead(Command command) async {
    final nodeId = _resolveNodeId(command);
    final variant = await _session.read(nodeId);
    return CommandResult(
      status: CommandStatus.completed,
      result: {
        'nodeId': nodeId.toStandardString(),
        'value': variant.value,
        'kind': variant.kind.name,
      },
    );
  }

  /// `opcua.browse` returns a list of reference descriptions reachable from
  /// the supplied NodeId. Args:
  ///   - target / args.namespace+args.numeric+args.string: NodeId source.
  ///   - args.maxResults (int, optional): cap the number of references.
  Future<CommandResult> _doBrowse(Command command) async {
    final from = _resolveNodeId(command);
    final maxResults = command.args['maxResults'] as int?;
    final refs = await _session.browse(from, maxResults: maxResults);
    return CommandResult(
      status: CommandStatus.completed,
      result: {
        'from': from.toStandardString(),
        'references': [for (final r in refs) r.toJson()],
      },
    );
  }

  /// `opcua.call_method` invokes an OPC UA Method.
  /// Args:
  ///   - object: NodeId of the target object (string form, e.g. `ns=2;i=1`).
  ///   - method: NodeId of the method.
  ///   - inputs (List, optional): argument values converted via
  ///     [OpcUaVariant.fromDart].
  Future<CommandResult> _doCallMethod(Command command) async {
    final objectArg = command.args['object'] as String?;
    final methodArg = command.args['method'] as String?;
    if (objectArg == null || methodArg == null) {
      return _argError('opcua.call_method requires args["object"] and args["method"]');
    }
    final object = OpcUaNodeId.parse(objectArg);
    final method = OpcUaNodeId.parse(methodArg);
    final inputs = (command.args['inputs'] as List?)
            ?.map(OpcUaVariant.fromDart)
            .toList() ??
        const <OpcUaVariant>[];
    final r = await _session.callMethod(object, method, inputs);
    return CommandResult(
      status: r.isGood ? CommandStatus.completed : CommandStatus.failed,
      result: {
        'object': object.toStandardString(),
        'method': method.toStandardString(),
        'statusCode': r.statusCode,
        'outputs': [for (final v in r.outputArguments) v.value],
      },
      error: r.isGood
          ? null
          : IoError(
              code: 'protocol.method_failed',
              message: 'OPC UA method returned 0x${r.statusCode.toRadixString(16)}',
              timestamp: DateTime.now(),
            ),
    );
  }

  /// `opcua.history_read` fetches historic data points for a NodeId.
  /// Args:
  ///   - target / namespace+numeric|string: NodeId.
  ///   - from / to (ISO-8601 strings): time window.
  ///   - maxValues (int, optional).
  Future<CommandResult> _doHistoryRead(Command command) async {
    final nodeId = _resolveNodeId(command);
    final fromArg = command.args['from'] as String?;
    final toArg = command.args['to'] as String?;
    if (fromArg == null || toArg == null) {
      return _argError('opcua.history_read requires args["from"] and args["to"] (ISO-8601)');
    }
    final from = DateTime.parse(fromArg);
    final to = DateTime.parse(toArg);
    final maxValues = command.args['maxValues'] as int?;
    final points = await _session.historyRead(
      nodeId, from: from, to: to, maxValues: maxValues,
    );
    return CommandResult(
      status: CommandStatus.completed,
      result: {
        'nodeId': nodeId.toStandardString(),
        'from': from.toIso8601String(),
        'to': to.toIso8601String(),
        'count': points.length,
        'points': [for (final p in points) p.toJson()],
      },
    );
  }

  /// Returns a confirmation that the target NodeId / event-type is parseable;
  /// the actual stream is obtained from the [subscribe] primitive.
  CommandResult _doSubscribeAck(Command command) {
    try {
      _resolveNodeId(command);
    } on Object catch (e) {
      return _argError('invalid NodeId: $e');
    }
    return CommandResult(
      status: CommandStatus.completed,
      result: {'nodeId': _resolveNodeId(command).toStandardString()},
    );
  }

  CommandResult _argError(String reason) => CommandResult(
        status: CommandStatus.rejected,
        error: IoError(
          code: 'exec.invalid_args',
          message: reason,
          timestamp: DateTime.now(),
        ),
      );

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
