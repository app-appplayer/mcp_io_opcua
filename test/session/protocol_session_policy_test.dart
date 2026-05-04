/// Integration test: drive `OpcUaProtocolSession` with a custom
/// security policy through the paired in-memory byte transport.
///
/// The session and the fake server share the same `_XorPolicy` so the
/// wire bytes are XOR-masked but the OPN handshake roundtrips
/// correctly. A control test repeats the flow with mismatched
/// policies and verifies the handshake fails.
@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:test/test.dart';

class _XorPolicy extends OpcUaSecurityPolicy {
  _XorPolicy(this.mask);
  final int mask;

  @override
  String get policyUri => 'http://test.local/UA/SecurityPolicy#Xor';

  @override
  bool get isNone => false;

  Uint8List _xor(List<int> bytes) {
    final out = Uint8List(bytes.length);
    for (var i = 0; i < bytes.length; i++) {
      out[i] = bytes[i] ^ mask;
    }
    return out;
  }

  @override
  Uint8List signOutboundOpn(List<int> body) => _xor(body);
  @override
  Uint8List unsealInboundOpn(List<int> body) => _xor(body);
  @override
  Uint8List signOutboundSymmetric(List<int> body) => _xor(body);
  @override
  Uint8List unsealInboundSymmetric(List<int> body) => _xor(body);
}

class _PolicyAwareServer {
  _PolicyAwareServer(this.transport, this.policy) {
    transport.incoming.listen(_pump.feed);
    _pump.frames.listen(_onFrame);
  }

  final InMemoryOpcUaByteTransport transport;
  final OpcUaSecurityPolicy policy;
  final OpcUaFramePump _pump = OpcUaFramePump();

  /// Tracks whether a successful OPN response was sent — the test
  /// uses this as the success signal in the mismatched-policy
  /// scenario.
  bool opnAcknowledged = false;

  void _onFrame(OpcUaWireFrame frame) {
    if (frame.messageType != 'OPN') return;
    try {
      _onOpnFrameUnsafe(frame);
    } on Object {
      // Mismatched policy or otherwise garbled frame — drop silently
      // so the client times out instead of crashing the listener.
    }
  }

  void _onOpnFrameUnsafe(OpcUaWireFrame frame) {
    final parsed =
        OpcUaSecureChannelFrame.decode(frame.bytes, policy: policy);
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
      asymmetric: OpcUaAsymmetricSecurityHeader(
        securityPolicyUri: policy.policyUri,
      ),
      sequence: parsed.sequence,
      body: body.takeBytes(),
      policy: policy,
    ));
    opnAcknowledged = true;
  }
}

OpcUaApplicationDescription _client() => const OpcUaApplicationDescription(
      applicationUri: 'urn:test',
      productUri: 'urn:test:product',
      applicationName: OpcUaLocalizedText(text: 'Test'),
    );

void main() {
  group('OpcUaProtocolSession SecurityPolicy propagation', () {
    test('TC-PSP-001 None default — handshake roundtrips (BC)', () async {
      final clientT = InMemoryOpcUaByteTransport();
      final serverT = InMemoryOpcUaByteTransport();
      clientT.pairWith(serverT);
      // Server uses None too.
      _PolicyAwareServer(serverT, const NoneSecurityPolicy());
      await serverT.open();

      final session = OpcUaProtocolSession(
        transport: clientT,
        endpoint: Uri.parse('opc.tcp://localhost:4840'),
        clientDescription: _client(),
      );
      await session.open();
      final r = await session.openSecureChannel();
      expect(r.securityToken.channelId, 1);
      expect(session.securityPolicy.isNone, isTrue);
      await session.close();
      await serverT.close();
    });

    test('TC-PSP-002 matching XOR policy on both ends — OPN succeeds',
        () async {
      final clientT = InMemoryOpcUaByteTransport();
      final serverT = InMemoryOpcUaByteTransport();
      clientT.pairWith(serverT);
      final policy = _XorPolicy(0x5A);
      _PolicyAwareServer(serverT, policy);
      await serverT.open();

      final session = OpcUaProtocolSession(
        transport: clientT,
        endpoint: Uri.parse('opc.tcp://localhost:4840'),
        clientDescription: _client(),
        securityPolicy: policy,
      );
      await session.open();
      final r = await session.openSecureChannel();
      expect(r.securityToken.channelId, 1);
      expect(session.securityPolicy.policyUri,
          'http://test.local/UA/SecurityPolicy#Xor');
      await session.close();
      await serverT.close();
    });

    test('TC-PSP-003 mismatched policy — client OPN times out', () async {
      final clientT = InMemoryOpcUaByteTransport();
      final serverT = InMemoryOpcUaByteTransport();
      clientT.pairWith(serverT);
      // Server uses one mask, client uses another.
      _PolicyAwareServer(serverT, _XorPolicy(0x5A));
      await serverT.open();

      final session = OpcUaProtocolSession(
        transport: clientT,
        endpoint: Uri.parse('opc.tcp://localhost:4840'),
        clientDescription: _client(),
        defaultTimeout: const Duration(milliseconds: 80),
        securityPolicy: _XorPolicy(0xA5),
      );
      await session.open();
      await expectLater(session.openSecureChannel(), throwsA(anything));
      await session.close();
      await serverT.close();
    });

    test('TC-PSP-004 OPN frame carries the policy URI in the asymmetric '
        'header', () async {
      final clientT = InMemoryOpcUaByteTransport();
      final serverT = InMemoryOpcUaByteTransport();
      clientT.pairWith(serverT);
      _PolicyAwareServer(serverT, _XorPolicy(0x5A));
      await serverT.open();

      final session = OpcUaProtocolSession(
        transport: clientT,
        endpoint: Uri.parse('opc.tcp://localhost:4840'),
        clientDescription: _client(),
        securityPolicy: _XorPolicy(0x5A),
      );
      await session.open();
      await session.openSecureChannel();

      // The very first sent packet is the OPN. Decode its asymmetric
      // header (with the same policy) and confirm the URI matches.
      final firstFrame = clientT.sent.first;
      final decoded = OpcUaSecureChannelFrame.decode(
        firstFrame.toList(),
        policy: _XorPolicy(0x5A),
      );
      expect(decoded.asymmetric, isNotNull);
      expect(decoded.asymmetric!.securityPolicyUri,
          'http://test.local/UA/SecurityPolicy#Xor');

      await session.close();
      await serverT.close();
    });
  });
}
