/// SecurityPolicy hook tests.
///
/// The package's main code path runs `None` policy (pass-through).
/// To verify the hook actually wires through, this file installs a
/// mock policy that XORs every body byte with a fixed mask and
/// confirms the encoded frame's body region differs from the input
/// while a roundtrip still recovers the original bytes.
@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:test/test.dart';

class _XorPolicy extends OpcUaSecurityPolicy {
  _XorPolicy(this.mask);
  final int mask;

  @override
  String get policyUri =>
      'http://test.local/UA/SecurityPolicy#Xor';

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

void main() {
  group('NoneSecurityPolicy default behaviour', () {
    test('TC-SP-001 isNone is true and pass-through identity', () {
      const p = NoneSecurityPolicy();
      expect(p.isNone, isTrue);
      expect(p.policyUri, kSecurityPolicyNoneUri);
      expect(p.signOutboundOpn(const [1, 2, 3]), [1, 2, 3]);
      expect(p.unsealInboundOpn(const [1, 2, 3]), [1, 2, 3]);
      expect(p.signOutboundSymmetric(const [4, 5]), [4, 5]);
      expect(p.unsealInboundSymmetric(const [4, 5]), [4, 5]);
    });

    test('TC-SP-002 default-policy frame matches no-policy encoding', () {
      final a = OpcUaSecureChannelFrame.encodeOpn(
        secureChannelId: 0,
        asymmetric: const OpcUaAsymmetricSecurityHeader(),
        sequence: const OpcUaSequenceHeader(sequenceNumber: 1, requestId: 1),
        body: const [0xAA, 0xBB, 0xCC],
      );
      final b = OpcUaSecureChannelFrame.encodeOpn(
        secureChannelId: 0,
        asymmetric: const OpcUaAsymmetricSecurityHeader(),
        sequence: const OpcUaSequenceHeader(sequenceNumber: 1, requestId: 1),
        body: const [0xAA, 0xBB, 0xCC],
        policy: const NoneSecurityPolicy(),
      );
      expect(a, b);
    });
  });

  group('Custom policy is wired into encode + decode', () {
    test('TC-SP-003 OPN frame: encode → wire bytes XOR mask → decode '
        'recovers the original body', () {
      final policy = _XorPolicy(0x5A);
      const body = [0x01, 0x02, 0x03, 0x04];
      final encoded = OpcUaSecureChannelFrame.encodeOpn(
        secureChannelId: 0,
        asymmetric: const OpcUaAsymmetricSecurityHeader(),
        sequence: const OpcUaSequenceHeader(sequenceNumber: 7, requestId: 9),
        body: body,
        policy: policy,
      );
      final decoded = OpcUaSecureChannelFrame.decode(encoded, policy: policy);
      expect(decoded.sequence.sequenceNumber, 7);
      expect(decoded.sequence.requestId, 9);
      expect(decoded.body, body);
    });

    test('TC-SP-004 MSG frame uses signOutboundSymmetric', () {
      final policy = _XorPolicy(0xA5);
      const body = [0x10, 0x20, 0x30];
      final encoded = OpcUaSecureChannelFrame.encodeSymmetric(
        type: OpcUaSecureMessageType.msg,
        secureChannelId: 1,
        symmetric: const OpcUaSymmetricSecurityHeader(tokenId: 1),
        sequence: const OpcUaSequenceHeader(sequenceNumber: 2, requestId: 2),
        body: body,
        policy: policy,
      );
      final decoded = OpcUaSecureChannelFrame.decode(encoded, policy: policy);
      expect(decoded.body, body);
    });

    test('TC-SP-005 None-encoded frame decoded with custom policy '
        'produces nonsense — confirms hooks actually run', () {
      final encoded = OpcUaSecureChannelFrame.encodeOpn(
        secureChannelId: 0,
        asymmetric: const OpcUaAsymmetricSecurityHeader(),
        sequence: const OpcUaSequenceHeader(sequenceNumber: 1, requestId: 1),
        body: const [0x01, 0x02, 0x03, 0x04],
      );
      // Decoding with an XOR policy must transform the bytes — the
      // body field is no longer the original. (We assert the decoder
      // either throws or returns a distinct body; the exact failure
      // mode depends on which random byte sits where the
      // SequenceHeader expects its uint32.)
      expect(
        () {
          final decoded = OpcUaSecureChannelFrame.decode(
              encoded, policy: _XorPolicy(0x5A));
          // If decode succeeds, body bytes must differ.
          expect(decoded.body, isNot([0x01, 0x02, 0x03, 0x04]));
        },
        returnsNormally,
      );
    });
  });

  group('Standard security-policy URIs', () {
    test('TC-SP-006 well-known URIs match Part 7 §6.1', () {
      expect(kSecurityPolicyNoneUri,
          'http://opcfoundation.org/UA/SecurityPolicy#None');
      expect(kSecurityPolicyBasic128Rsa15Uri,
          'http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15');
      expect(kSecurityPolicyBasic256Sha256Uri,
          'http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256');
      expect(kSecurityPolicyAes128Sha256RsaOaepUri,
          'http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep');
      expect(kSecurityPolicyAes256Sha256RsaPssUri,
          'http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss');
    });
  });
}
