/// MonitoredItems service set codecs (OPC UA Part 4 §5.12).
library;

import '../encoding/binary_reader.dart';
import '../encoding/binary_writer.dart';
import '../encoding/extension_object_codec.dart';
import '../encoding/node_id_codec.dart';
import 'read_service.dart';
import 'request_header.dart';

/// Monitoring mode (Part 4 §7.20). Selects how the server samples + reports.
enum OpcUaMonitoringMode {
  disabled(0),
  sampling(1),
  reporting(2);

  const OpcUaMonitoringMode(this.id);
  final int id;

  static OpcUaMonitoringMode fromId(int id) {
    if (id < 0 || id > 2) {
      throw ArgumentError.value(id, 'id', 'invalid MonitoringMode');
    }
    return OpcUaMonitoringMode.values[id];
  }
}

/// `MonitoringParameters` (Part 4 §7.21).
class OpcUaMonitoringParameters {
  /// Caller-chosen handle. Echoed in `MonitoredItemNotification.clientHandle`.
  final int clientHandle;

  /// Sampling interval in ms. Negative values use the publishing interval.
  final double samplingInterval;

  /// Optional filter (DataChangeFilter / EventFilter / AggregateFilter).
  final OpcUaExtensionObject filter;

  final int queueSize;
  final bool discardOldest;

  OpcUaMonitoringParameters({
    required this.clientHandle,
    this.samplingInterval = -1,
    OpcUaExtensionObject? filter,
    this.queueSize = 1,
    this.discardOldest = true,
  }) : filter = filter ?? _nullFilter;

  void encode(BinaryWriter w) {
    w.writeUint32(clientHandle);
    w.writeFloat64(samplingInterval);
    ExtensionObjectCodec.encode(w, filter);
    w.writeUint32(queueSize);
    w.writeUint8(discardOldest ? 1 : 0);
  }

  factory OpcUaMonitoringParameters.decode(BinaryReader r) {
    return OpcUaMonitoringParameters(
      clientHandle: r.readUint32(),
      samplingInterval: r.readFloat64(),
      filter: ExtensionObjectCodec.decode(r),
      queueSize: r.readUint32(),
      discardOldest: r.readUint8() != 0,
    );
  }

  static final _nullFilter = OpcUaExtensionObject(
    typeId: const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 0),
    encoding: ExtensionObjectEncoding.noBody,
  );
}

class OpcUaMonitoredItemCreateRequest {
  final OpcUaReadValueId itemToMonitor;
  final OpcUaMonitoringMode monitoringMode;
  final OpcUaMonitoringParameters requestedParameters;

  const OpcUaMonitoredItemCreateRequest({
    required this.itemToMonitor,
    this.monitoringMode = OpcUaMonitoringMode.reporting,
    required this.requestedParameters,
  });

  void encode(BinaryWriter w) {
    itemToMonitor.encode(w);
    w.writeUint32(monitoringMode.id);
    requestedParameters.encode(w);
  }

  factory OpcUaMonitoredItemCreateRequest.decode(BinaryReader r) {
    return OpcUaMonitoredItemCreateRequest(
      itemToMonitor: OpcUaReadValueId.decode(r),
      monitoringMode: OpcUaMonitoringMode.fromId(r.readUint32()),
      requestedParameters: OpcUaMonitoringParameters.decode(r),
    );
  }
}

class OpcUaMonitoredItemCreateResult {
  final int statusCode;
  final int monitoredItemId;
  final double revisedSamplingInterval;
  final int revisedQueueSize;
  final OpcUaExtensionObject filterResult;

  OpcUaMonitoredItemCreateResult({
    this.statusCode = 0,
    this.monitoredItemId = 0,
    this.revisedSamplingInterval = 0,
    this.revisedQueueSize = 1,
    OpcUaExtensionObject? filterResult,
  }) : filterResult = filterResult ?? _nullFilter;

  void encode(BinaryWriter w) {
    w.writeUint32(statusCode);
    w.writeUint32(monitoredItemId);
    w.writeFloat64(revisedSamplingInterval);
    w.writeUint32(revisedQueueSize);
    ExtensionObjectCodec.encode(w, filterResult);
  }

  factory OpcUaMonitoredItemCreateResult.decode(BinaryReader r) {
    return OpcUaMonitoredItemCreateResult(
      statusCode: r.readUint32(),
      monitoredItemId: r.readUint32(),
      revisedSamplingInterval: r.readFloat64(),
      revisedQueueSize: r.readUint32(),
      filterResult: ExtensionObjectCodec.decode(r),
    );
  }

  static final _nullFilter = OpcUaExtensionObject(
    typeId: const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 0),
    encoding: ExtensionObjectEncoding.noBody,
  );
}

class OpcUaCreateMonitoredItemsRequest {
  final OpcUaRequestHeader header;
  final int subscriptionId;
  final OpcUaTimestampsToReturn timestampsToReturn;
  final List<OpcUaMonitoredItemCreateRequest> itemsToCreate;

  const OpcUaCreateMonitoredItemsRequest({
    required this.header,
    required this.subscriptionId,
    this.timestampsToReturn = OpcUaTimestampsToReturn.both,
    required this.itemsToCreate,
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    w.writeUint32(subscriptionId);
    w.writeUint32(timestampsToReturn.id);
    w.writeInt32(itemsToCreate.length);
    for (final m in itemsToCreate) {
      m.encode(w);
    }
  }

  factory OpcUaCreateMonitoredItemsRequest.decode(BinaryReader r) {
    final header = OpcUaRequestHeader.decode(r);
    final scid = r.readUint32();
    final ts = OpcUaTimestampsToReturn.fromId(r.readUint32());
    final n = r.readInt32();
    final list = <OpcUaMonitoredItemCreateRequest>[
      for (var i = 0; i < n; i++) OpcUaMonitoredItemCreateRequest.decode(r),
    ];
    return OpcUaCreateMonitoredItemsRequest(
      header: header,
      subscriptionId: scid,
      timestampsToReturn: ts,
      itemsToCreate: list,
    );
  }
}

class OpcUaCreateMonitoredItemsResponse {
  final OpcUaResponseHeader header;
  final List<OpcUaMonitoredItemCreateResult> results;
  final List<int> diagnosticInfoMasks;

  const OpcUaCreateMonitoredItemsResponse({
    required this.header,
    required this.results,
    this.diagnosticInfoMasks = const [],
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    w.writeInt32(results.length);
    for (final m in results) {
      m.encode(w);
    }
    if (diagnosticInfoMasks.isEmpty) {
      w.writeInt32(-1);
    } else {
      w.writeInt32(diagnosticInfoMasks.length);
      for (final m in diagnosticInfoMasks) {
        w.writeUint8(m);
      }
    }
  }

  factory OpcUaCreateMonitoredItemsResponse.decode(BinaryReader r) {
    final header = OpcUaResponseHeader.decode(r);
    final n = r.readInt32();
    final rows = <OpcUaMonitoredItemCreateResult>[
      for (var i = 0; i < n; i++) OpcUaMonitoredItemCreateResult.decode(r),
    ];
    final dn = r.readInt32();
    final diag = <int>[];
    if (dn > 0) {
      for (var i = 0; i < dn; i++) {
        final m = r.readUint8();
        if (m != 0) {
          throw StateError(
            'OpcUaCreateMonitoredItemsResponse: '
            'non-empty DiagnosticInfo not supported',
          );
        }
        diag.add(m);
      }
    }
    return OpcUaCreateMonitoredItemsResponse(
      header: header, results: rows, diagnosticInfoMasks: diag,
    );
  }
}

class OpcUaDeleteMonitoredItemsRequest {
  final OpcUaRequestHeader header;
  final int subscriptionId;
  final List<int> monitoredItemIds;

  const OpcUaDeleteMonitoredItemsRequest({
    required this.header,
    required this.subscriptionId,
    required this.monitoredItemIds,
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    w.writeUint32(subscriptionId);
    w.writeInt32(monitoredItemIds.length);
    for (final id in monitoredItemIds) {
      w.writeUint32(id);
    }
  }

  factory OpcUaDeleteMonitoredItemsRequest.decode(BinaryReader r) {
    final header = OpcUaRequestHeader.decode(r);
    final scid = r.readUint32();
    final n = r.readInt32();
    final ids = <int>[for (var i = 0; i < n; i++) r.readUint32()];
    return OpcUaDeleteMonitoredItemsRequest(
      header: header, subscriptionId: scid, monitoredItemIds: ids,
    );
  }
}

class OpcUaDeleteMonitoredItemsResponse {
  final OpcUaResponseHeader header;
  final List<int> results;
  final List<int> diagnosticInfoMasks;

  const OpcUaDeleteMonitoredItemsResponse({
    required this.header,
    required this.results,
    this.diagnosticInfoMasks = const [],
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    w.writeInt32(results.length);
    for (final c in results) {
      w.writeUint32(c);
    }
    if (diagnosticInfoMasks.isEmpty) {
      w.writeInt32(-1);
    } else {
      w.writeInt32(diagnosticInfoMasks.length);
      for (final m in diagnosticInfoMasks) {
        w.writeUint8(m);
      }
    }
  }

  factory OpcUaDeleteMonitoredItemsResponse.decode(BinaryReader r) {
    final header = OpcUaResponseHeader.decode(r);
    final n = r.readInt32();
    final codes = <int>[for (var i = 0; i < n; i++) r.readUint32()];
    final dn = r.readInt32();
    final diag = <int>[];
    if (dn > 0) {
      for (var i = 0; i < dn; i++) {
        final m = r.readUint8();
        if (m != 0) {
          throw StateError(
            'OpcUaDeleteMonitoredItemsResponse: '
            'non-empty DiagnosticInfo not supported',
          );
        }
        diag.add(m);
      }
    }
    return OpcUaDeleteMonitoredItemsResponse(
      header: header, results: codes, diagnosticInfoMasks: diag,
    );
  }
}
