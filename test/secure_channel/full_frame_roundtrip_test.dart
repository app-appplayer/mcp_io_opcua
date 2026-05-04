/// Full SecureChannel frame roundtrip tests with Basic256Sha256.
///
/// Drives `OpcUaSecureChannelFrame.encodeOpn` / `encodeSymmetric`
/// against a `Basic256Sha256SecurityPolicy` instance whose RSA keys
/// are generated in-suite, then decodes the produced wire bytes with
/// the *peer* policy (own/peer keys swapped). Verifies:
///   * The full frame bytes are non-trivially different from the
///     plaintext (encryption actually happened).
///   * Decode recovers the exact `seq + body` bytes the sender wrote.
///   * Tampering with any byte after the message header causes decode
///     to throw.
///   * MSG/CLO frames roundtrip with channel keys derived from the
///     OPN nonces.
@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:pointycastle/api.dart' as pc;
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'package:pointycastle/random/fortuna_random.dart';
import 'package:test/test.dart';

pc.AsymmetricKeyPair<OpcUaRsaPublicKey, OpcUaRsaPrivateKey> _genKeyPair(int seed) {
  final rnd = FortunaRandom()
    ..seed(pc.KeyParameter(
        Uint8List.fromList(List<int>.generate(32, (i) => i + seed))));
  final gen = RSAKeyGenerator()
    ..init(pc.ParametersWithRandom(
      RSAKeyGeneratorParameters(BigInt.parse('65537'), 2048, 64),
      rnd,
    ));
  final pair = gen.generateKeyPair();
  return pc.AsymmetricKeyPair(
    pair.publicKey as OpcUaRsaPublicKey,
    pair.privateKey as OpcUaRsaPrivateKey,
  );
}

void main() {
  late pc.AsymmetricKeyPair<OpcUaRsaPublicKey, OpcUaRsaPrivateKey> client;
  late pc.AsymmetricKeyPair<OpcUaRsaPublicKey, OpcUaRsaPrivateKey> server;
  setUpAll(() {
    client = _genKeyPair(11);
    server = _genKeyPair(23);
  });

  group('OPN full-frame roundtrip', () {
    test('TC-FF-001 client encode → server decode recovers body', () {
      final clientPolicy = Basic256Sha256SecurityPolicy(
        ownPrivateKey: client.privateKey,
        peerPublicKey: server.publicKey,
        isClient: true,
      );
      final serverPolicy = Basic256Sha256SecurityPolicy(
        ownPrivateKey: server.privateKey,
        peerPublicKey: client.publicKey,
        isClient: false,
      );

      const body = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
      final asym = OpcUaAsymmetricSecurityHeader(
        securityPolicyUri: kSecurityPolicyBasic256Sha256Uri,
        senderCertificate: [0xCA, 0xFE, 0xBA, 0xBE], // dummy cert bytes
        receiverCertificateThumbprint:
            List<int>.generate(20, (i) => i),
      );

      final frame = OpcUaSecureChannelFrame.encodeOpn(
        secureChannelId: 0,
        asymmetric: asym,
        sequence:
            const OpcUaSequenceHeader(sequenceNumber: 1, requestId: 1),
        body: body,
        policy: clientPolicy,
      );

      final decoded = OpcUaSecureChannelFrame.decode(
        frame,
        policy: serverPolicy,
      );

      expect(decoded.type, OpcUaSecureMessageType.opn);
      expect(decoded.body, body);
      expect(decoded.sequence.sequenceNumber, 1);
      expect(decoded.sequence.requestId, 1);
      expect(decoded.asymmetric?.securityPolicyUri,
          kSecurityPolicyBasic256Sha256Uri);
    });

    test('TC-FF-002 wire bytes differ from plaintext (encryption happened)',
        () {
      final clientPolicy = Basic256Sha256SecurityPolicy(
        ownPrivateKey: client.privateKey,
        peerPublicKey: server.publicKey,
        isClient: true,
      );
      final body = List<int>.generate(64, (i) => i & 0xFF);
      final asym = OpcUaAsymmetricSecurityHeader(
        securityPolicyUri: kSecurityPolicyBasic256Sha256Uri,
        senderCertificate: [0xCA, 0xFE],
        receiverCertificateThumbprint: List<int>.generate(20, (i) => i),
      );

      final frame = OpcUaSecureChannelFrame.encodeOpn(
        secureChannelId: 0,
        asymmetric: asym,
        sequence:
            const OpcUaSequenceHeader(sequenceNumber: 1, requestId: 1),
        body: body,
        policy: clientPolicy,
      );

      // The body bytes (as written) shouldn't appear contiguously in
      // the wire frame — the encrypted region replaces them.
      final hay = String.fromCharCodes(frame);
      final needle = String.fromCharCodes(body);
      expect(hay.contains(needle), isFalse,
          reason: 'body bytes leaked into encrypted frame');
    });

    test('TC-FF-003 tampered ciphertext fails decode', () {
      final clientPolicy = Basic256Sha256SecurityPolicy(
        ownPrivateKey: client.privateKey,
        peerPublicKey: server.publicKey,
        isClient: true,
      );
      final serverPolicy = Basic256Sha256SecurityPolicy(
        ownPrivateKey: server.privateKey,
        peerPublicKey: client.publicKey,
        isClient: false,
      );

      const body = [10, 20, 30, 40];
      final asym = OpcUaAsymmetricSecurityHeader(
        securityPolicyUri: kSecurityPolicyBasic256Sha256Uri,
        senderCertificate: [0xAA],
        receiverCertificateThumbprint: List<int>.generate(20, (i) => i),
      );

      final frame = OpcUaSecureChannelFrame.encodeOpn(
        secureChannelId: 0,
        asymmetric: asym,
        sequence:
            const OpcUaSequenceHeader(sequenceNumber: 1, requestId: 1),
        body: body,
        policy: clientPolicy,
      );

      // Flip a byte deep in the ciphertext region (away from headers).
      final tampered = Uint8List.fromList(frame);
      tampered[tampered.length - 5] ^= 0x01;

      expect(
        () => OpcUaSecureChannelFrame.decode(tampered, policy: serverPolicy),
        throwsA(anything),
      );
    });
  });

  group('Symmetric MSG full-frame roundtrip', () {
    test('TC-FF-004 MSG roundtrips with bound channel keys', () {
      final clientNonce = List<int>.generate(32, (i) => i);
      final serverNonce = List<int>.generate(32, (i) => 32 - i);
      final keys = Basic256Sha256SecurityPolicy.deriveChannelKeys(
        clientNonce: clientNonce,
        serverNonce: serverNonce,
      );

      final clientPolicy = Basic256Sha256SecurityPolicy(
        ownPrivateKey: client.privateKey,
        peerPublicKey: server.publicKey,
        isClient: true,
      )..bindChannelKeys(keys);
      final serverPolicy = Basic256Sha256SecurityPolicy(
        ownPrivateKey: server.privateKey,
        peerPublicKey: client.publicKey,
        isClient: false,
      )..bindChannelKeys(keys);

      const body = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
      final frame = OpcUaSecureChannelFrame.encodeSymmetric(
        type: OpcUaSecureMessageType.msg,
        secureChannelId: 7,
        symmetric: const OpcUaSymmetricSecurityHeader(tokenId: 42),
        sequence:
            const OpcUaSequenceHeader(sequenceNumber: 5, requestId: 5),
        body: body,
        policy: clientPolicy,
      );

      final decoded = OpcUaSecureChannelFrame.decode(
        frame,
        policy: serverPolicy,
      );

      expect(decoded.type, OpcUaSecureMessageType.msg);
      expect(decoded.body, body);
      expect(decoded.symmetric?.tokenId, 42);
      expect(decoded.sequence.sequenceNumber, 5);
    });

    test('TC-FF-005 server → client direction roundtrips', () {
      final keys = Basic256Sha256SecurityPolicy.deriveChannelKeys(
        clientNonce: List<int>.generate(32, (i) => i),
        serverNonce: List<int>.generate(32, (i) => 100 - i),
      );

      final clientPolicy = Basic256Sha256SecurityPolicy(
        ownPrivateKey: client.privateKey,
        peerPublicKey: server.publicKey,
        isClient: true,
      )..bindChannelKeys(keys);
      final serverPolicy = Basic256Sha256SecurityPolicy(
        ownPrivateKey: server.privateKey,
        peerPublicKey: client.publicKey,
        isClient: false,
      )..bindChannelKeys(keys);

      // Server sends; client decodes.
      final frame = OpcUaSecureChannelFrame.encodeSymmetric(
        type: OpcUaSecureMessageType.msg,
        secureChannelId: 9,
        symmetric: const OpcUaSymmetricSecurityHeader(tokenId: 99),
        sequence:
            const OpcUaSequenceHeader(sequenceNumber: 99, requestId: 99),
        body: const [0x01, 0x02, 0x03],
        policy: serverPolicy,
      );
      final decoded = OpcUaSecureChannelFrame.decode(
        frame,
        policy: clientPolicy,
      );
      expect(decoded.body, [0x01, 0x02, 0x03]);
    });
  });

  group('Backward compat: None policy still works', () {
    test('TC-FF-006 None encode → None decode unchanged', () {
      const body = [1, 2, 3];
      final frame = OpcUaSecureChannelFrame.encodeOpn(
        secureChannelId: 0,
        asymmetric: const OpcUaAsymmetricSecurityHeader(),
        sequence:
            const OpcUaSequenceHeader(sequenceNumber: 1, requestId: 1),
        body: body,
      );
      final decoded = OpcUaSecureChannelFrame.decode(frame);
      expect(decoded.body, body);
    });
  });
}
