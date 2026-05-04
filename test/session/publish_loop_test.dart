/// `OpcUaPublishLoop` integration tests.
///
/// Reuses the paired in-memory byte transport pattern from
/// `protocol_session_test.dart`: a hand-rolled fake server responds
/// to `Publish` requests with synthetic notification messages so we
/// can verify routing, ack accumulation, and lifecycle.
library;

import 'dart:async';

import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:test/test.dart';

class _PublishOnlyServer {
  _PublishOnlyServer(this.transport) {
    transport.incoming.listen(_pump.feed);
    _pump.frames.listen(_onFrame);
  }

  final InMemoryOpcUaByteTransport transport;
  final OpcUaFramePump _pump = OpcUaFramePump();
  final int subscriptionId = 7;

  /// Server-side sequence number for synthetic notifications.
  int seq = 0;

  /// Acks observed in the most recent PublishRequest — exposed for
  /// test assertions.
  final List<OpcUaSubscriptionAcknowledgement> lastAcks = [];

  void _onFrame(OpcUaWireFrame frame) {
    if (frame.messageType == 'OPN') {
      _respondOpn(frame);
      return;
    }
    if (frame.messageType != 'MSG') return;
    final parsed = OpcUaSecureChannelFrame.decode(frame.bytes);
    final reader = BinaryReader(parsed.body);
    final typeId = NodeIdCodec.decode(reader);
    if (typeId is! OpcUaNodeIdNumeric) return;
    if (typeId.identifier == kOpcUaNodeIdPublishRequest) {
      _respondPublish(parsed, reader);
    }
  }

  void _respondOpn(OpcUaWireFrame frame) {
    final parsed = OpcUaSecureChannelFrame.decode(frame.bytes);
    final reader = BinaryReader(parsed.body);
    NodeIdCodec.decode(reader);
    final req = OpcUaOpenSecureChannelRequest.decode(reader);
    final body = BinaryWriter();
    NodeIdCodec.encode(
      body,
      const OpcUaNodeIdNumeric(
        namespaceIndex: 0,
        identifier: kOpcUaNodeIdOpenSecureChannelResponse,
      ),
    );
    OpcUaOpenSecureChannelResponse(
      header: OpcUaResponseHeader(
        timestamp: DateTime.now().toUtc(),
        requestHandle: req.header.requestHandle,
      ),
      securityToken: OpcUaChannelSecurityToken(
        channelId: 1, tokenId: 1,
        createdAt: DateTime.now().toUtc(),
        revisedLifetime: req.requestedLifetime,
      ),
    ).encode(body);
    transport.send(OpcUaSecureChannelFrame.encodeOpn(
      secureChannelId: 1,
      asymmetric: const OpcUaAsymmetricSecurityHeader(),
      sequence: parsed.sequence,
      body: body.takeBytes(),
    ));
  }

  void _respondPublish(
      OpcUaSecureChannelFrame inFrame, BinaryReader reader) {
    final req = OpcUaPublishRequest.decode(reader);
    lastAcks
      ..clear()
      ..addAll(req.subscriptionAcknowledgements);
    seq++;

    final notif = OpcUaNotificationMessage(
      sequenceNumber: seq,
      publishTime: DateTime.now().toUtc(),
      notificationData: const [],
    );
    final body = BinaryWriter();
    NodeIdCodec.encode(
      body,
      const OpcUaNodeIdNumeric(
        namespaceIndex: 0,
        identifier: kOpcUaNodeIdPublishResponse,
      ),
    );
    OpcUaPublishResponse(
      header: OpcUaResponseHeader(
        timestamp: DateTime.now().toUtc(),
        requestHandle: req.header.requestHandle,
      ),
      subscriptionId: subscriptionId,
      availableSequenceNumbers: const [],
      moreNotifications: false,
      notificationMessage: notif,
      results: [
        for (var i = 0; i < req.subscriptionAcknowledgements.length; i++) 0,
      ],
    ).encode(body);

    transport.send(OpcUaSecureChannelFrame.encodeSymmetric(
      type: OpcUaSecureMessageType.msg,
      secureChannelId: 1,
      symmetric: const OpcUaSymmetricSecurityHeader(tokenId: 1),
      sequence: OpcUaSequenceHeader(
        sequenceNumber: seq + 100,
        requestId: inFrame.sequence.requestId,
      ),
      body: body.takeBytes(),
    ));
  }
}

void main() {
  group('OpcUaPublishLoop', () {
    late InMemoryOpcUaByteTransport clientT;
    late InMemoryOpcUaByteTransport serverT;
    late _PublishOnlyServer server;
    late OpcUaProtocolSession session;
    OpcUaPublishLoop? loop;

    setUp(() async {
      clientT = InMemoryOpcUaByteTransport();
      serverT = InMemoryOpcUaByteTransport();
      clientT.pairWith(serverT);
      server = _PublishOnlyServer(serverT);
      // ignore: unused_local_variable
      final _ = server;
      await serverT.open();

      session = OpcUaProtocolSession(
        transport: clientT,
        endpoint: Uri.parse('opc.tcp://localhost:4840'),
        clientDescription: const OpcUaApplicationDescription(
          applicationUri: 'urn:test',
          productUri: 'urn:test:product',
          applicationName: OpcUaLocalizedText(text: 'Test'),
        ),
      );
      await session.open();
      await session.openSecureChannel();
    });

    tearDown(() async {
      await loop?.stop();
      await session.close();
      await serverT.close();
    });

    test('TC-PL-001 register/unregister updates subscriptionIds', () async {
      loop = OpcUaPublishLoop(session: session);
      expect(loop!.subscriptionIds, isEmpty);
      loop!.register(7);
      loop!.register(8);
      expect(loop!.subscriptionIds, {7, 8});
      await loop!.unregister(7);
      expect(loop!.subscriptionIds, {8});
    });

    test(
        'TC-PL-002 register-twice keeps a single underlying controller — '
        'both streams see the same events', () async {
      loop = OpcUaPublishLoop(session: session, maxInFlight: 1);
      final s1 = loop!.register(7);
      final s2 = loop!.register(7);
      // subscriptionIds must report a single id (not two registrations).
      expect(loop!.subscriptionIds, {7});
      // Listen on both streams. A real notification routed by the loop
      // is observed by both — confirming a single underlying controller.
      final r1 = <OpcUaNotificationMessage>[];
      final r2 = <OpcUaNotificationMessage>[];
      final a = s1.listen(r1.add);
      final b = s2.listen(r2.add);
      await loop!.start();
      // Wait for at least one notification on s1.
      await s1.first.timeout(const Duration(seconds: 3));
      expect(r1, isNotEmpty);
      expect(r2, isNotEmpty);
      await a.cancel();
      await b.cancel();
    });

    test('TC-PL-003 isRunning toggles around start/stop', () async {
      loop = OpcUaPublishLoop(session: session);
      expect(loop!.isRunning, isFalse);
      await loop!.start();
      expect(loop!.isRunning, isTrue);
      await loop!.stop();
      expect(loop!.isRunning, isFalse);
    });

    test('TC-PL-004 stop closes per-subscription streams', () async {
      loop = OpcUaPublishLoop(session: session);
      final stream = loop!.register(7);
      var doneFired = false;
      final sub = stream.listen((_) {}, onDone: () => doneFired = true);
      await loop!.stop();
      // Allow the onDone microtask to fire.
      await Future<void>.delayed(Duration.zero);
      expect(doneFired, isTrue);
      await sub.cancel();
    });

    test('TC-PL-005 single notification routes to the registered stream',
        () async {
      loop = OpcUaPublishLoop(session: session, maxInFlight: 1);
      final stream = loop!.register(7);
      final firstMsg = stream.first;
      await loop!.start();
      final notif = await firstMsg.timeout(const Duration(seconds: 3));
      expect(notif.sequenceNumber, 1);
    });
  });
}
