import 'dart:typed_data';

import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:test/test.dart';

OpcUaRequestHeader _hdr({int handle = 1}) => OpcUaRequestHeader(
      authenticationToken:
          const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 0),
      timestamp: DateTime.utc(2026, 5, 3),
      requestHandle: handle,
    );

OpcUaResponseHeader _rhdr({int handle = 1, int sc = 0}) => OpcUaResponseHeader(
      timestamp: DateTime.utc(2026, 5, 3),
      requestHandle: handle,
      serviceResult: sc,
    );

void main() {
  group('CreateSubscription', () {
    test('TC-CS-001 request roundtrip', () {
      final req = OpcUaCreateSubscriptionRequest(
        header: _hdr(),
        requestedPublishingInterval: 250,
        requestedLifetimeCount: 120,
        requestedMaxKeepAliveCount: 20,
        maxNotificationsPerPublish: 1000,
        publishingEnabled: true,
        priority: 5,
      );
      final w = BinaryWriter();
      req.encode(w);
      final back =
          OpcUaCreateSubscriptionRequest.decode(BinaryReader(w.takeBytes()));
      expect(back.requestedPublishingInterval, 250);
      expect(back.requestedLifetimeCount, 120);
      expect(back.requestedMaxKeepAliveCount, 20);
      expect(back.maxNotificationsPerPublish, 1000);
      expect(back.publishingEnabled, isTrue);
      expect(back.priority, 5);
    });

    test('TC-CS-002 response roundtrip with revised values', () {
      final resp = OpcUaCreateSubscriptionResponse(
        header: _rhdr(),
        subscriptionId: 42,
        revisedPublishingInterval: 500,
        revisedLifetimeCount: 200,
        revisedMaxKeepAliveCount: 30,
      );
      final w = BinaryWriter();
      resp.encode(w);
      final back =
          OpcUaCreateSubscriptionResponse.decode(BinaryReader(w.takeBytes()));
      expect(back.subscriptionId, 42);
      expect(back.revisedPublishingInterval, 500);
      expect(back.revisedLifetimeCount, 200);
      expect(back.revisedMaxKeepAliveCount, 30);
    });
  });

  group('ModifySubscription', () {
    test('TC-MS-001 request + response roundtrip', () {
      final req = OpcUaModifySubscriptionRequest(
        header: _hdr(),
        subscriptionId: 7,
        requestedPublishingInterval: 100,
      );
      final wr = BinaryWriter();
      req.encode(wr);
      final reqBack =
          OpcUaModifySubscriptionRequest.decode(BinaryReader(wr.takeBytes()));
      expect(reqBack.subscriptionId, 7);

      final resp = OpcUaModifySubscriptionResponse(
        header: _rhdr(),
        revisedPublishingInterval: 100,
        revisedLifetimeCount: 60,
        revisedMaxKeepAliveCount: 10,
      );
      final wr2 = BinaryWriter();
      resp.encode(wr2);
      final back = OpcUaModifySubscriptionResponse.decode(
          BinaryReader(wr2.takeBytes()));
      expect(back.revisedPublishingInterval, 100);
    });
  });

  group('DeleteSubscriptions', () {
    test('TC-DS-001 ids + per-row results roundtrip', () {
      final req = OpcUaDeleteSubscriptionsRequest(
        header: _hdr(),
        subscriptionIds: const [1, 2, 3],
      );
      final wr = BinaryWriter();
      req.encode(wr);
      final reqBack = OpcUaDeleteSubscriptionsRequest.decode(
          BinaryReader(wr.takeBytes()));
      expect(reqBack.subscriptionIds, [1, 2, 3]);

      final resp = OpcUaDeleteSubscriptionsResponse(
        header: _rhdr(),
        results: const [0, 0x80370000, 0],
      );
      final wr2 = BinaryWriter();
      resp.encode(wr2);
      final back = OpcUaDeleteSubscriptionsResponse.decode(
          BinaryReader(wr2.takeBytes()));
      expect(back.results, [0, 0x80370000, 0]);
    });
  });

  group('SetPublishingMode', () {
    test('TC-SPM-001 enabled toggle + ids + results', () {
      final req = OpcUaSetPublishingModeRequest(
        header: _hdr(),
        publishingEnabled: false,
        subscriptionIds: const [10, 20],
      );
      final wr = BinaryWriter();
      req.encode(wr);
      final reqBack = OpcUaSetPublishingModeRequest.decode(
          BinaryReader(wr.takeBytes()));
      expect(reqBack.publishingEnabled, isFalse);
      expect(reqBack.subscriptionIds, [10, 20]);
    });
  });

  group('Publish / NotificationMessage', () {
    test('TC-PB-001 publish request with subscription acknowledgements', () {
      final req = OpcUaPublishRequest(
        header: _hdr(),
        subscriptionAcknowledgements: const [
          OpcUaSubscriptionAcknowledgement(
              subscriptionId: 1, sequenceNumber: 5),
          OpcUaSubscriptionAcknowledgement(
              subscriptionId: 2, sequenceNumber: 6),
        ],
      );
      final wr = BinaryWriter();
      req.encode(wr);
      final back = OpcUaPublishRequest.decode(BinaryReader(wr.takeBytes()));
      expect(back.subscriptionAcknowledgements, hasLength(2));
      expect(back.subscriptionAcknowledgements[0].subscriptionId, 1);
      expect(back.subscriptionAcknowledgements[1].sequenceNumber, 6);
    });

    test('TC-PB-002 publish response with NotificationMessage roundtrip',
        () {
      final notif = OpcUaNotificationMessage(
        sequenceNumber: 42,
        publishTime: DateTime.utc(2026, 5, 3, 12, 0, 0),
        notificationData: const [],
      );
      final resp = OpcUaPublishResponse(
        header: _rhdr(),
        subscriptionId: 7,
        availableSequenceNumbers: const [40, 41],
        moreNotifications: false,
        notificationMessage: notif,
        results: const [0, 0],
      );
      final wr = BinaryWriter();
      resp.encode(wr);
      final back =
          OpcUaPublishResponse.decode(BinaryReader(wr.takeBytes()));
      expect(back.subscriptionId, 7);
      expect(back.availableSequenceNumbers, [40, 41]);
      expect(back.moreNotifications, isFalse);
      expect(back.notificationMessage.sequenceNumber, 42);
      expect(back.results, [0, 0]);
    });

    test('TC-PB-003 NotificationMessage with notificationData ExtensionObjects',
        () {
      final notif = OpcUaNotificationMessage(
        sequenceNumber: 1,
        publishTime: DateTime.utc(2026, 5, 3),
        notificationData: [
          OpcUaExtensionObject(
            typeId:
                const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 811),
            encoding: ExtensionObjectEncoding.byteString,
            body: Uint8List.fromList(const [0x01, 0x02, 0x03]),
          ),
        ],
      );
      final w = BinaryWriter();
      notif.encode(w);
      final back =
          OpcUaNotificationMessage.decode(BinaryReader(w.takeBytes()));
      expect(back.notificationData, hasLength(1));
      expect(back.notificationData[0].body, [0x01, 0x02, 0x03]);
    });
  });
}
