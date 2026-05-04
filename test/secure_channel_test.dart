import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:test/test.dart';

void main() {
  group('OpcUaSecureChannelFrame — OPN encode/decode roundtrip', () {
    test('TC-SC-001 None policy: null cert + null thumbprint', () {
      final encoded = OpcUaSecureChannelFrame.encodeOpn(
        secureChannelId: 0, // OPN request: SecureChannelId 0 = new channel
        asymmetric: const OpcUaAsymmetricSecurityHeader(),
        sequence: const OpcUaSequenceHeader(sequenceNumber: 1, requestId: 1),
        body: const [0x01, 0x02, 0x03],
      );
      // Header sanity: "OPNF" + length + scid=0.
      expect(String.fromCharCodes(encoded.sublist(0, 3)), 'OPN');
      expect(String.fromCharCode(encoded[3]), 'F');

      final decoded = OpcUaSecureChannelFrame.decode(encoded);
      expect(decoded.type, OpcUaSecureMessageType.opn);
      expect(decoded.chunk, OpcUaChunkType.finalChunk);
      expect(decoded.secureChannelId, 0);
      expect(decoded.asymmetric, isNotNull);
      expect(decoded.asymmetric!.securityPolicyUri, kOpcUaSecurityPolicyNoneUri);
      expect(decoded.asymmetric!.senderCertificate, isNull);
      expect(decoded.asymmetric!.receiverCertificateThumbprint, isNull);
      expect(decoded.sequence.sequenceNumber, 1);
      expect(decoded.sequence.requestId, 1);
      expect(decoded.body, [0x01, 0x02, 0x03]);
    });

    test('TC-SC-002 OPN preserves non-null cert + thumbprint', () {
      final cert = List<int>.generate(64, (i) => i & 0xFF);
      final thumb = List<int>.generate(20, (i) => 0xAA);
      final encoded = OpcUaSecureChannelFrame.encodeOpn(
        secureChannelId: 0,
        asymmetric: OpcUaAsymmetricSecurityHeader(
          securityPolicyUri:
              'http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256',
          senderCertificate: cert,
          receiverCertificateThumbprint: thumb,
        ),
        sequence: const OpcUaSequenceHeader(sequenceNumber: 7, requestId: 9),
        body: const [],
      );
      final decoded = OpcUaSecureChannelFrame.decode(encoded);
      expect(decoded.asymmetric!.senderCertificate, cert);
      expect(decoded.asymmetric!.receiverCertificateThumbprint, thumb);
      expect(decoded.asymmetric!.securityPolicyUri,
          'http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256');
      expect(decoded.asymmetric!.isNonePolicy, isFalse);
    });
  });

  group('OpcUaSecureChannelFrame — MSG / CLO encode/decode roundtrip', () {
    test('TC-SC-003 MSG with symmetric tokenId + body bytes', () {
      final body = [for (var i = 0; i < 32; i++) i & 0xFF];
      final encoded = OpcUaSecureChannelFrame.encodeSymmetric(
        type: OpcUaSecureMessageType.msg,
        secureChannelId: 0xDEADBEEF,
        symmetric: const OpcUaSymmetricSecurityHeader(tokenId: 7),
        sequence: const OpcUaSequenceHeader(sequenceNumber: 42, requestId: 100),
        body: body,
      );
      expect(String.fromCharCodes(encoded.sublist(0, 3)), 'MSG');

      final decoded = OpcUaSecureChannelFrame.decode(encoded);
      expect(decoded.type, OpcUaSecureMessageType.msg);
      expect(decoded.secureChannelId, 0xDEADBEEF);
      expect(decoded.symmetric!.tokenId, 7);
      expect(decoded.sequence.sequenceNumber, 42);
      expect(decoded.sequence.requestId, 100);
      expect(decoded.body, body);
    });

    test('TC-SC-004 CLO frame uses symmetric encoding', () {
      final encoded = OpcUaSecureChannelFrame.encodeSymmetric(
        type: OpcUaSecureMessageType.clo,
        secureChannelId: 1,
        symmetric: const OpcUaSymmetricSecurityHeader(tokenId: 1),
        sequence: const OpcUaSequenceHeader(sequenceNumber: 99, requestId: 99),
        body: const [],
      );
      expect(String.fromCharCodes(encoded.sublist(0, 3)), 'CLO');
      final decoded = OpcUaSecureChannelFrame.decode(encoded);
      expect(decoded.type, OpcUaSecureMessageType.clo);
      expect(decoded.symmetric!.tokenId, 1);
      expect(decoded.body, isEmpty);
    });

    test('TC-SC-005 encodeSymmetric rejects OPN type', () {
      expect(
        () => OpcUaSecureChannelFrame.encodeSymmetric(
          type: OpcUaSecureMessageType.opn,
          secureChannelId: 0,
          symmetric: const OpcUaSymmetricSecurityHeader(tokenId: 0),
          sequence:
              const OpcUaSequenceHeader(sequenceNumber: 1, requestId: 1),
          body: const [],
        ),
        throwsA(isA<OpcUaProtocolError>()),
      );
    });
  });

  group('OpcUaSecureChannelFrame — header validation', () {
    test('TC-SC-006 truncated frame raises protocol error', () {
      expect(
        () => OpcUaSecureChannelFrame.decode(const [0x4F, 0x50]),
        throwsA(isA<OpcUaProtocolError>()),
      );
    });

    test('TC-SC-007 size mismatch detected', () {
      // 12-byte header but message size set to 99.
      final buf = [
        ...'MSG'.codeUnits,
        0x46, // 'F'
        99, 0, 0, 0, // size = 99 (LE)
        0, 0, 0, 0, // SecureChannelId
      ];
      expect(
        () => OpcUaSecureChannelFrame.decode(buf),
        throwsA(isA<OpcUaProtocolError>()),
      );
    });

    test('TC-SC-008 intermediate chunk type roundtrips', () {
      final encoded = OpcUaSecureChannelFrame.encodeSymmetric(
        type: OpcUaSecureMessageType.msg,
        secureChannelId: 1,
        symmetric: const OpcUaSymmetricSecurityHeader(tokenId: 1),
        sequence: const OpcUaSequenceHeader(sequenceNumber: 1, requestId: 1),
        body: const [0x10],
        chunk: OpcUaChunkType.intermediate,
      );
      final decoded = OpcUaSecureChannelFrame.decode(encoded);
      expect(decoded.chunk, OpcUaChunkType.intermediate);
    });
  });
}
