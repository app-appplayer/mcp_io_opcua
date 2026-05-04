/// Subscription service set codecs (OPC UA Part 4 §5.13).
///
/// Contained services:
///   - `CreateSubscription` (§5.13.2)
///   - `ModifySubscription` (§5.13.3)
///   - `DeleteSubscriptions` (§5.13.5)
///   - `SetPublishingMode` (§5.13.4)
///   - `Publish` / `Republish` (§5.13.6 / §5.13.7) — including
///     `NotificationMessage`. The body of the per-subscription
///     `notificationData` field is carried as raw `OpcUaExtensionObject`
///     so callers can plug in `DataChangeNotification` / `EventNotification`
///     / `StatusChangeNotification` decoders on top.
library;

import '../encoding/binary_reader.dart';
import '../encoding/binary_writer.dart';
import '../encoding/extension_object_codec.dart';
import 'request_header.dart';

// === CreateSubscription ===

class OpcUaCreateSubscriptionRequest {
  final OpcUaRequestHeader header;
  final double requestedPublishingInterval;
  final int requestedLifetimeCount;
  final int requestedMaxKeepAliveCount;
  final int maxNotificationsPerPublish;
  final bool publishingEnabled;
  final int priority;

  const OpcUaCreateSubscriptionRequest({
    required this.header,
    this.requestedPublishingInterval = 1000,
    this.requestedLifetimeCount = 60,
    this.requestedMaxKeepAliveCount = 10,
    this.maxNotificationsPerPublish = 0,
    this.publishingEnabled = true,
    this.priority = 0,
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    w.writeFloat64(requestedPublishingInterval);
    w.writeUint32(requestedLifetimeCount);
    w.writeUint32(requestedMaxKeepAliveCount);
    w.writeUint32(maxNotificationsPerPublish);
    w.writeUint8(publishingEnabled ? 1 : 0);
    w.writeUint8(priority);
  }

  factory OpcUaCreateSubscriptionRequest.decode(BinaryReader r) {
    final header = OpcUaRequestHeader.decode(r);
    return OpcUaCreateSubscriptionRequest(
      header: header,
      requestedPublishingInterval: r.readFloat64(),
      requestedLifetimeCount: r.readUint32(),
      requestedMaxKeepAliveCount: r.readUint32(),
      maxNotificationsPerPublish: r.readUint32(),
      publishingEnabled: r.readUint8() != 0,
      priority: r.readUint8(),
    );
  }
}

class OpcUaCreateSubscriptionResponse {
  final OpcUaResponseHeader header;
  final int subscriptionId;
  final double revisedPublishingInterval;
  final int revisedLifetimeCount;
  final int revisedMaxKeepAliveCount;

  const OpcUaCreateSubscriptionResponse({
    required this.header,
    required this.subscriptionId,
    required this.revisedPublishingInterval,
    required this.revisedLifetimeCount,
    required this.revisedMaxKeepAliveCount,
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    w.writeUint32(subscriptionId);
    w.writeFloat64(revisedPublishingInterval);
    w.writeUint32(revisedLifetimeCount);
    w.writeUint32(revisedMaxKeepAliveCount);
  }

  factory OpcUaCreateSubscriptionResponse.decode(BinaryReader r) {
    return OpcUaCreateSubscriptionResponse(
      header: OpcUaResponseHeader.decode(r),
      subscriptionId: r.readUint32(),
      revisedPublishingInterval: r.readFloat64(),
      revisedLifetimeCount: r.readUint32(),
      revisedMaxKeepAliveCount: r.readUint32(),
    );
  }
}

// === ModifySubscription ===

class OpcUaModifySubscriptionRequest {
  final OpcUaRequestHeader header;
  final int subscriptionId;
  final double requestedPublishingInterval;
  final int requestedLifetimeCount;
  final int requestedMaxKeepAliveCount;
  final int maxNotificationsPerPublish;
  final int priority;

  const OpcUaModifySubscriptionRequest({
    required this.header,
    required this.subscriptionId,
    this.requestedPublishingInterval = 1000,
    this.requestedLifetimeCount = 60,
    this.requestedMaxKeepAliveCount = 10,
    this.maxNotificationsPerPublish = 0,
    this.priority = 0,
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    w.writeUint32(subscriptionId);
    w.writeFloat64(requestedPublishingInterval);
    w.writeUint32(requestedLifetimeCount);
    w.writeUint32(requestedMaxKeepAliveCount);
    w.writeUint32(maxNotificationsPerPublish);
    w.writeUint8(priority);
  }

  factory OpcUaModifySubscriptionRequest.decode(BinaryReader r) {
    return OpcUaModifySubscriptionRequest(
      header: OpcUaRequestHeader.decode(r),
      subscriptionId: r.readUint32(),
      requestedPublishingInterval: r.readFloat64(),
      requestedLifetimeCount: r.readUint32(),
      requestedMaxKeepAliveCount: r.readUint32(),
      maxNotificationsPerPublish: r.readUint32(),
      priority: r.readUint8(),
    );
  }
}

class OpcUaModifySubscriptionResponse {
  final OpcUaResponseHeader header;
  final double revisedPublishingInterval;
  final int revisedLifetimeCount;
  final int revisedMaxKeepAliveCount;

  const OpcUaModifySubscriptionResponse({
    required this.header,
    required this.revisedPublishingInterval,
    required this.revisedLifetimeCount,
    required this.revisedMaxKeepAliveCount,
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    w.writeFloat64(revisedPublishingInterval);
    w.writeUint32(revisedLifetimeCount);
    w.writeUint32(revisedMaxKeepAliveCount);
  }

  factory OpcUaModifySubscriptionResponse.decode(BinaryReader r) {
    return OpcUaModifySubscriptionResponse(
      header: OpcUaResponseHeader.decode(r),
      revisedPublishingInterval: r.readFloat64(),
      revisedLifetimeCount: r.readUint32(),
      revisedMaxKeepAliveCount: r.readUint32(),
    );
  }
}

// === DeleteSubscriptions ===

class OpcUaDeleteSubscriptionsRequest {
  final OpcUaRequestHeader header;
  final List<int> subscriptionIds;

  const OpcUaDeleteSubscriptionsRequest({
    required this.header,
    required this.subscriptionIds,
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    w.writeInt32(subscriptionIds.length);
    for (final id in subscriptionIds) {
      w.writeUint32(id);
    }
  }

  factory OpcUaDeleteSubscriptionsRequest.decode(BinaryReader r) {
    final header = OpcUaRequestHeader.decode(r);
    final n = r.readInt32();
    final ids = <int>[for (var i = 0; i < n; i++) r.readUint32()];
    return OpcUaDeleteSubscriptionsRequest(
      header: header, subscriptionIds: ids,
    );
  }
}

class OpcUaDeleteSubscriptionsResponse {
  final OpcUaResponseHeader header;
  final List<int> results;
  final List<int> diagnosticInfoMasks;

  const OpcUaDeleteSubscriptionsResponse({
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

  factory OpcUaDeleteSubscriptionsResponse.decode(BinaryReader r) {
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
            'OpcUaDeleteSubscriptionsResponse: '
            'non-empty DiagnosticInfo not supported',
          );
        }
        diag.add(m);
      }
    }
    return OpcUaDeleteSubscriptionsResponse(
      header: header, results: codes, diagnosticInfoMasks: diag,
    );
  }
}

// === SetPublishingMode ===

class OpcUaSetPublishingModeRequest {
  final OpcUaRequestHeader header;
  final bool publishingEnabled;
  final List<int> subscriptionIds;

  const OpcUaSetPublishingModeRequest({
    required this.header,
    required this.publishingEnabled,
    required this.subscriptionIds,
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    w.writeUint8(publishingEnabled ? 1 : 0);
    w.writeInt32(subscriptionIds.length);
    for (final id in subscriptionIds) {
      w.writeUint32(id);
    }
  }

  factory OpcUaSetPublishingModeRequest.decode(BinaryReader r) {
    final header = OpcUaRequestHeader.decode(r);
    final enabled = r.readUint8() != 0;
    final n = r.readInt32();
    final ids = <int>[for (var i = 0; i < n; i++) r.readUint32()];
    return OpcUaSetPublishingModeRequest(
      header: header, publishingEnabled: enabled, subscriptionIds: ids,
    );
  }
}

class OpcUaSetPublishingModeResponse {
  final OpcUaResponseHeader header;
  final List<int> results;
  final List<int> diagnosticInfoMasks;

  const OpcUaSetPublishingModeResponse({
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

  factory OpcUaSetPublishingModeResponse.decode(BinaryReader r) {
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
            'OpcUaSetPublishingModeResponse: '
            'non-empty DiagnosticInfo not supported',
          );
        }
        diag.add(m);
      }
    }
    return OpcUaSetPublishingModeResponse(
      header: header, results: codes, diagnosticInfoMasks: diag,
    );
  }
}

// === Publish / Republish ===

class OpcUaSubscriptionAcknowledgement {
  final int subscriptionId;
  final int sequenceNumber;

  const OpcUaSubscriptionAcknowledgement({
    required this.subscriptionId,
    required this.sequenceNumber,
  });

  void encode(BinaryWriter w) {
    w.writeUint32(subscriptionId);
    w.writeUint32(sequenceNumber);
  }

  factory OpcUaSubscriptionAcknowledgement.decode(BinaryReader r) =>
      OpcUaSubscriptionAcknowledgement(
        subscriptionId: r.readUint32(),
        sequenceNumber: r.readUint32(),
      );
}

class OpcUaPublishRequest {
  final OpcUaRequestHeader header;
  final List<OpcUaSubscriptionAcknowledgement> subscriptionAcknowledgements;

  const OpcUaPublishRequest({
    required this.header,
    this.subscriptionAcknowledgements = const [],
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    if (subscriptionAcknowledgements.isEmpty) {
      w.writeInt32(-1);
    } else {
      w.writeInt32(subscriptionAcknowledgements.length);
      for (final a in subscriptionAcknowledgements) {
        a.encode(w);
      }
    }
  }

  factory OpcUaPublishRequest.decode(BinaryReader r) {
    final header = OpcUaRequestHeader.decode(r);
    final n = r.readInt32();
    final acks = <OpcUaSubscriptionAcknowledgement>[];
    if (n > 0) {
      for (var i = 0; i < n; i++) {
        acks.add(OpcUaSubscriptionAcknowledgement.decode(r));
      }
    }
    return OpcUaPublishRequest(
      header: header, subscriptionAcknowledgements: acks,
    );
  }
}

/// `NotificationMessage` (Part 4 §7.21).
class OpcUaNotificationMessage {
  final int sequenceNumber;
  final DateTime publishTime;
  final List<OpcUaExtensionObject> notificationData;

  const OpcUaNotificationMessage({
    required this.sequenceNumber,
    required this.publishTime,
    this.notificationData = const [],
  });

  void encode(BinaryWriter w) {
    w.writeUint32(sequenceNumber);
    w.writeInt64(_dateTimeToTicks(publishTime));
    if (notificationData.isEmpty) {
      w.writeInt32(-1);
    } else {
      w.writeInt32(notificationData.length);
      for (final eo in notificationData) {
        ExtensionObjectCodec.encode(w, eo);
      }
    }
  }

  factory OpcUaNotificationMessage.decode(BinaryReader r) {
    final seq = r.readUint32();
    final ts = _ticksToDateTime(r.readInt64());
    final n = r.readInt32();
    final data = <OpcUaExtensionObject>[];
    if (n > 0) {
      for (var i = 0; i < n; i++) {
        data.add(ExtensionObjectCodec.decode(r));
      }
    }
    return OpcUaNotificationMessage(
      sequenceNumber: seq, publishTime: ts, notificationData: data,
    );
  }
}

class OpcUaPublishResponse {
  final OpcUaResponseHeader header;
  final int subscriptionId;
  final List<int> availableSequenceNumbers;
  final bool moreNotifications;
  final OpcUaNotificationMessage notificationMessage;

  /// Per-acknowledgement StatusCodes (matched by index against
  /// `OpcUaPublishRequest.subscriptionAcknowledgements`).
  final List<int> results;
  final List<int> diagnosticInfoMasks;

  const OpcUaPublishResponse({
    required this.header,
    required this.subscriptionId,
    required this.availableSequenceNumbers,
    required this.moreNotifications,
    required this.notificationMessage,
    this.results = const [],
    this.diagnosticInfoMasks = const [],
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    w.writeUint32(subscriptionId);
    if (availableSequenceNumbers.isEmpty) {
      w.writeInt32(-1);
    } else {
      w.writeInt32(availableSequenceNumbers.length);
      for (final n in availableSequenceNumbers) {
        w.writeUint32(n);
      }
    }
    w.writeUint8(moreNotifications ? 1 : 0);
    notificationMessage.encode(w);
    if (results.isEmpty) {
      w.writeInt32(-1);
    } else {
      w.writeInt32(results.length);
      for (final c in results) {
        w.writeUint32(c);
      }
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

  factory OpcUaPublishResponse.decode(BinaryReader r) {
    final header = OpcUaResponseHeader.decode(r);
    final scid = r.readUint32();
    final ac = r.readInt32();
    final available = <int>[];
    if (ac > 0) {
      for (var i = 0; i < ac; i++) {
        available.add(r.readUint32());
      }
    }
    final more = r.readUint8() != 0;
    final notif = OpcUaNotificationMessage.decode(r);
    final rc = r.readInt32();
    final results = <int>[];
    if (rc > 0) {
      for (var i = 0; i < rc; i++) {
        results.add(r.readUint32());
      }
    }
    final dn = r.readInt32();
    final diag = <int>[];
    if (dn > 0) {
      for (var i = 0; i < dn; i++) {
        final m = r.readUint8();
        if (m != 0) {
          throw StateError(
            'OpcUaPublishResponse: non-empty DiagnosticInfo not supported',
          );
        }
        diag.add(m);
      }
    }
    return OpcUaPublishResponse(
      header: header,
      subscriptionId: scid,
      availableSequenceNumbers: available,
      moreNotifications: more,
      notificationMessage: notif,
      results: results,
      diagnosticInfoMasks: diag,
    );
  }
}

const int _epochOffsetMicros = -11644473600000000;

int _dateTimeToTicks(DateTime dt) =>
    (dt.toUtc().microsecondsSinceEpoch - _epochOffsetMicros) * 10;

DateTime _ticksToDateTime(int ticks) =>
    DateTime.fromMicrosecondsSinceEpoch(
        (ticks ~/ 10) + _epochOffsetMicros, isUtc: true);
