/// Notification body codecs carried inside `NotificationMessage.notificationData`
/// ExtensionObject entries (OPC UA Part 4 §7.16, §7.18).
///
/// Three concrete bodies are recognised:
///   - `DataChangeNotification` — variable-value updates per
///     monitored item.
///   - `EventNotificationList` — alarm / event field updates.
///   - `StatusChangeNotification` — subscription status transitions
///     (e.g. KeepAlive → reporting).
///
/// Higher-level code typically iterates `NotificationMessage.notificationData`,
/// dispatches by the ExtensionObject's typeId (the constants in
/// `service_node_ids.dart`), and decodes the body via the matching
/// `…fromExtension` factory.
library;

import 'dart:typed_data';

import '../encoding/binary_reader.dart';
import '../encoding/binary_writer.dart';
import '../encoding/data_value_codec.dart';
import '../encoding/extension_object_codec.dart';
import '../encoding/node_id_codec.dart';
import '../encoding/variant_codec.dart';
import 'service_node_ids.dart';

/// Single entry inside a [OpcUaDataChangeNotification].
class OpcUaMonitoredItemNotification {
  /// Caller-chosen handle from `MonitoringParameters.clientHandle`.
  final int clientHandle;

  /// Latest reported sample.
  final OpcUaDataValue value;

  const OpcUaMonitoredItemNotification({
    required this.clientHandle,
    required this.value,
  });

  void encode(BinaryWriter w) {
    w.writeUint32(clientHandle);
    DataValueCodec.encode(w, value);
  }

  factory OpcUaMonitoredItemNotification.decode(BinaryReader r) {
    return OpcUaMonitoredItemNotification(
      clientHandle: r.readUint32(),
      value: DataValueCodec.decode(r),
    );
  }
}

/// `DataChangeNotification` — the most common notification body
/// (Part 4 §7.16).
class OpcUaDataChangeNotification {
  final List<OpcUaMonitoredItemNotification> monitoredItems;

  /// `0` mask byte per row when no diagnostics. Kept symmetric with
  /// the rest of the codec stack (full DiagnosticInfo decoder is
  /// deferred).
  final List<int> diagnosticInfoMasks;

  const OpcUaDataChangeNotification({
    required this.monitoredItems,
    this.diagnosticInfoMasks = const [],
  });

  void encode(BinaryWriter w) {
    w.writeInt32(monitoredItems.length);
    for (final m in monitoredItems) {
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

  factory OpcUaDataChangeNotification.decode(BinaryReader r) {
    final n = r.readInt32();
    final items = <OpcUaMonitoredItemNotification>[];
    if (n > 0) {
      for (var i = 0; i < n; i++) {
        items.add(OpcUaMonitoredItemNotification.decode(r));
      }
    }
    final dn = r.readInt32();
    final diag = <int>[];
    if (dn > 0) {
      for (var i = 0; i < dn; i++) {
        final m = r.readUint8();
        if (m != 0) {
          throw StateError(
            'OpcUaDataChangeNotification: '
            'non-empty DiagnosticInfo not supported',
          );
        }
        diag.add(m);
      }
    }
    return OpcUaDataChangeNotification(
      monitoredItems: items, diagnosticInfoMasks: diag,
    );
  }

  /// Wrap into the matching `ExtensionObject` (typeId 811).
  OpcUaExtensionObject toExtensionObject() {
    final w = BinaryWriter();
    encode(w);
    return OpcUaExtensionObject(
      typeId: const OpcUaNodeIdNumeric(
        namespaceIndex: 0,
        identifier: kOpcUaNodeIdDataChangeNotification,
      ),
      encoding: ExtensionObjectEncoding.byteString,
      body: Uint8List.fromList(w.takeBytes()),
    );
  }

  /// Decode from an [OpcUaExtensionObject] whose typeId is
  /// [kOpcUaNodeIdDataChangeNotification]. Throws when the typeId or
  /// encoding don't match.
  factory OpcUaDataChangeNotification.fromExtension(
      OpcUaExtensionObject eo) {
    _expectTypeId(eo, kOpcUaNodeIdDataChangeNotification);
    return OpcUaDataChangeNotification.decode(BinaryReader(eo.body!));
  }
}

/// One row inside [OpcUaEventNotificationList].
class OpcUaEventFieldList {
  /// Caller-chosen handle (matches the monitored-item that filtered
  /// the event).
  final int clientHandle;

  /// Field values, one per `EventFilter.selectClauses` entry.
  final List<OpcUaVariantValue> eventFields;

  const OpcUaEventFieldList({
    required this.clientHandle,
    required this.eventFields,
  });

  void encode(BinaryWriter w) {
    w.writeUint32(clientHandle);
    if (eventFields.isEmpty) {
      w.writeInt32(-1);
    } else {
      w.writeInt32(eventFields.length);
      for (final v in eventFields) {
        VariantCodec.encode(w, v);
      }
    }
  }

  factory OpcUaEventFieldList.decode(BinaryReader r) {
    final handle = r.readUint32();
    final n = r.readInt32();
    final fields = <OpcUaVariantValue>[];
    if (n > 0) {
      for (var i = 0; i < n; i++) {
        fields.add(VariantCodec.decode(r));
      }
    }
    return OpcUaEventFieldList(clientHandle: handle, eventFields: fields);
  }
}

/// `EventNotificationList` — alarm / event updates (Part 4 §7.18).
class OpcUaEventNotificationList {
  final List<OpcUaEventFieldList> events;

  const OpcUaEventNotificationList({required this.events});

  void encode(BinaryWriter w) {
    w.writeInt32(events.length);
    for (final e in events) {
      e.encode(w);
    }
  }

  factory OpcUaEventNotificationList.decode(BinaryReader r) {
    final n = r.readInt32();
    final list = <OpcUaEventFieldList>[
      for (var i = 0; i < n; i++) OpcUaEventFieldList.decode(r),
    ];
    return OpcUaEventNotificationList(events: list);
  }

  OpcUaExtensionObject toExtensionObject() {
    final w = BinaryWriter();
    encode(w);
    return OpcUaExtensionObject(
      typeId: const OpcUaNodeIdNumeric(
        namespaceIndex: 0,
        identifier: kOpcUaNodeIdEventNotificationList,
      ),
      encoding: ExtensionObjectEncoding.byteString,
      body: Uint8List.fromList(w.takeBytes()),
    );
  }

  factory OpcUaEventNotificationList.fromExtension(
      OpcUaExtensionObject eo) {
    _expectTypeId(eo, kOpcUaNodeIdEventNotificationList);
    return OpcUaEventNotificationList.decode(BinaryReader(eo.body!));
  }
}

/// `StatusChangeNotification` — subscription status transitions
/// (Part 4 §7.16).
class OpcUaStatusChangeNotification {
  /// OPC UA StatusCode reflecting the subscription's new state.
  final int status;

  /// `0` mask byte = no diagnostics; non-zero is rejected (deferred).
  final int diagnosticInfoMask;

  const OpcUaStatusChangeNotification({
    required this.status,
    this.diagnosticInfoMask = 0,
  });

  void encode(BinaryWriter w) {
    w.writeUint32(status);
    w.writeUint8(diagnosticInfoMask);
  }

  factory OpcUaStatusChangeNotification.decode(BinaryReader r) {
    final st = r.readUint32();
    final mask = r.readUint8();
    if (mask != 0) {
      throw StateError(
        'OpcUaStatusChangeNotification: '
        'non-empty DiagnosticInfo not supported',
      );
    }
    return OpcUaStatusChangeNotification(status: st);
  }

  OpcUaExtensionObject toExtensionObject() {
    final w = BinaryWriter();
    encode(w);
    return OpcUaExtensionObject(
      typeId: const OpcUaNodeIdNumeric(
        namespaceIndex: 0,
        identifier: kOpcUaNodeIdStatusChangeNotification,
      ),
      encoding: ExtensionObjectEncoding.byteString,
      body: Uint8List.fromList(w.takeBytes()),
    );
  }

  factory OpcUaStatusChangeNotification.fromExtension(
      OpcUaExtensionObject eo) {
    _expectTypeId(eo, kOpcUaNodeIdStatusChangeNotification);
    return OpcUaStatusChangeNotification.decode(BinaryReader(eo.body!));
  }
}

void _expectTypeId(OpcUaExtensionObject eo, int expected) {
  final id = eo.typeId;
  if (id is! OpcUaNodeIdNumeric ||
      id.namespaceIndex != 0 ||
      id.identifier != expected) {
    throw ArgumentError(
      'unexpected ExtensionObject typeId — expected ns=0;i=$expected, got $id',
    );
  }
  if (eo.encoding != ExtensionObjectEncoding.byteString || eo.body == null) {
    throw ArgumentError(
      'expected byteString-encoded ExtensionObject with non-null body',
    );
  }
}
