/// Tests for `Basic256Sha256SecurityPolicy`.
///
/// Verifies:
///   * Channel-key derivation matches the OPC UA Part 6 §6.7.5 layout
///     (32 sig + 32 enc + 16 IV per direction, 80 bytes total) and is
///     deterministic given fixed nonces.
///   * `signEncryptOpnInner` → `verifyDecryptOpnInner` roundtrip
///     recovers the original payload, including with the actual
///     header context attached.
///   * Tampering with the header context, ciphertext, or signature
///     causes verify to fail.
///   * Symmetric sign+encrypt → decrypt+verify roundtrip works,
///     including HMAC tamper detection.
///   * Frame-size pre-computation matches the actual encrypted bytes
///     length (so the framing layer can fill the size field before
///     signing).
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
    client = _genKeyPair(7);
    server = _genKeyPair(13);
  });

  group('Channel key derivation', () {
    test('TC-KDF-001 yields 32+32+16 layout per direction', () {
      final keys = Basic256Sha256SecurityPolicy.deriveChannelKeys(
        clientNonce: List<int>.generate(32, (i) => i),
        serverNonce: List<int>.generate(32, (i) => 32 - i),
      );
      expect(keys.clientSigning.length, 32);
      expect(keys.clientEncrypting.length, 32);
      expect(keys.clientIv.length, 16);
      expect(keys.serverSigning.length, 32);
      expect(keys.serverEncrypting.length, 32);
      expect(keys.serverIv.length, 16);
    });

    test('TC-KDF-002 client and server keys differ (P_SHA256 with swapped seed)',
        () {
      final keys = Basic256Sha256SecurityPolicy.deriveChannelKeys(
        clientNonce: List<int>.generate(32, (i) => i),
        serverNonce: List<int>.generate(32, (i) => 32 - i),
      );
      expect(keys.clientSigning, isNot(keys.serverSigning));
      expect(keys.clientEncrypting, isNot(keys.serverEncrypting));
      expect(keys.clientIv, isNot(keys.serverIv));
    });

    test('TC-KDF-003 deterministic for fixed nonces', () {
      final a = Basic256Sha256SecurityPolicy.deriveChannelKeys(
        clientNonce: List<int>.generate(32, (i) => i),
        serverNonce: List<int>.generate(32, (i) => 32 - i),
      );
      final b = Basic256Sha256SecurityPolicy.deriveChannelKeys(
        clientNonce: List<int>.generate(32, (i) => i),
        serverNonce: List<int>.generate(32, (i) => 32 - i),
      );
      expect(a.clientSigning, b.clientSigning);
      expect(a.serverEncrypting, b.serverEncrypting);
    });
  });

  group('Asymmetric OPN sign+encrypt roundtrip', () {
    test('TC-OPN-001 small body roundtrips', () {
      final policy = Basic256Sha256SecurityPolicy();
      final body = List<int>.generate(64, (i) => i & 0xFF);
      final headerContext = List<int>.generate(32, (i) => 0xA0 + (i & 0xF));

      final sealed = policy.signEncryptOpnInner(
        headerContext: headerContext,
        sequenceAndBody: body,
        peerPublicKey: server.publicKey,
        ourPrivateKey: client.privateKey,
      );

      final recovered = policy.verifyDecryptOpnInner(
        headerContext: headerContext,
        ciphertext: sealed,
        ourPrivateKey: server.privateKey,
        peerPublicKey: client.publicKey,
      );

      expect(recovered, body);
    });

    test('TC-OPN-002 multi-block body roundtrips', () {
      final policy = Basic256Sha256SecurityPolicy();
      // Force at least 3 plaintext blocks: each block holds 214 bytes,
      // signature occupies 256 bytes — body of 500 → ~3 blocks.
      final body = List<int>.generate(500, (i) => (i * 7) & 0xFF);
      final headerContext = Uint8List(28); // 12 msg header + 16 stub asym

      final sealed = policy.signEncryptOpnInner(
        headerContext: headerContext,
        sequenceAndBody: body,
        peerPublicKey: server.publicKey,
        ourPrivateKey: client.privateKey,
      );

      final recovered = policy.verifyDecryptOpnInner(
        headerContext: headerContext,
        ciphertext: sealed,
        ourPrivateKey: server.privateKey,
        peerPublicKey: client.publicKey,
      );

      expect(recovered, body);
    });

    test('TC-OPN-003 mismatched header context fails verification', () {
      final policy = Basic256Sha256SecurityPolicy();
      final body = List<int>.generate(64, (i) => i & 0xFF);
      final headerContext = List<int>.filled(32, 0xAA);

      final sealed = policy.signEncryptOpnInner(
        headerContext: headerContext,
        sequenceAndBody: body,
        peerPublicKey: server.publicKey,
        ourPrivateKey: client.privateKey,
      );

      expect(() => policy.verifyDecryptOpnInner(
        headerContext: List<int>.filled(32, 0xBB),
        ciphertext: sealed,
        ourPrivateKey: server.privateKey,
        peerPublicKey: client.publicKey,
      ), throwsA(isA<StateError>()));
    });

    test('TC-OPN-004 tampered ciphertext fails decryption', () {
      final policy = Basic256Sha256SecurityPolicy();
      final body = List<int>.generate(64, (i) => i & 0xFF);
      final headerContext = Uint8List(28);

      final sealed = policy.signEncryptOpnInner(
        headerContext: headerContext,
        sequenceAndBody: body,
        peerPublicKey: server.publicKey,
        ourPrivateKey: client.privateKey,
      );
      final tampered = Uint8List.fromList(sealed)..[10] ^= 0x01;

      expect(() => policy.verifyDecryptOpnInner(
        headerContext: headerContext,
        ciphertext: tampered,
        ourPrivateKey: server.privateKey,
        peerPublicKey: client.publicKey,
      ), throwsA(anything));
    });
  });

  group('Symmetric MSG sign+encrypt roundtrip', () {
    test('TC-SYM-001 roundtrips with derived channel keys', () {
      final policy = Basic256Sha256SecurityPolicy();
      final keys = Basic256Sha256SecurityPolicy.deriveChannelKeys(
        clientNonce: List<int>.generate(32, (i) => i),
        serverNonce: List<int>.generate(32, (i) => 32 - i),
      );
      final body = List<int>.generate(200, (i) => (i * 3) & 0xFF);
      final headerContext = Uint8List(16);

      final sealed = policy.signEncryptSymmetricInner(
        headerContext: headerContext,
        sequenceAndBody: body,
        signingKey: keys.clientSigning,
        encryptingKey: keys.clientEncrypting,
        iv: keys.clientIv,
      );

      final recovered = policy.verifyDecryptSymmetricInner(
        headerContext: headerContext,
        ciphertext: sealed,
        signingKey: keys.clientSigning,
        encryptingKey: keys.clientEncrypting,
        iv: keys.clientIv,
      );

      expect(recovered, body);
    });

    test('TC-SYM-002 wrong signing key fails verification', () {
      final policy = Basic256Sha256SecurityPolicy();
      final keys = Basic256Sha256SecurityPolicy.deriveChannelKeys(
        clientNonce: List<int>.generate(32, (i) => i),
        serverNonce: List<int>.generate(32, (i) => 32 - i),
      );
      final body = List<int>.generate(64, (i) => i & 0xFF);
      final headerContext = Uint8List(16);

      final sealed = policy.signEncryptSymmetricInner(
        headerContext: headerContext,
        sequenceAndBody: body,
        signingKey: keys.clientSigning,
        encryptingKey: keys.clientEncrypting,
        iv: keys.clientIv,
      );

      // Decrypt with right enc key but wrong signing key — HMAC fails.
      expect(() => policy.verifyDecryptSymmetricInner(
        headerContext: headerContext,
        ciphertext: sealed,
        signingKey: keys.serverSigning, // wrong
        encryptingKey: keys.clientEncrypting,
        iv: keys.clientIv,
      ), throwsA(isA<StateError>()));
    });

    test('TC-SYM-003 tampered header context fails HMAC', () {
      final policy = Basic256Sha256SecurityPolicy();
      final keys = Basic256Sha256SecurityPolicy.deriveChannelKeys(
        clientNonce: List<int>.generate(32, (i) => i),
        serverNonce: List<int>.generate(32, (i) => 32 - i),
      );
      final body = List<int>.generate(64, (i) => i & 0xFF);
      final headerContext = Uint8List.fromList(List<int>.filled(16, 0x01));

      final sealed = policy.signEncryptSymmetricInner(
        headerContext: headerContext,
        sequenceAndBody: body,
        signingKey: keys.clientSigning,
        encryptingKey: keys.clientEncrypting,
        iv: keys.clientIv,
      );

      expect(() => policy.verifyDecryptSymmetricInner(
        headerContext: Uint8List.fromList(List<int>.filled(16, 0x02)),
        ciphertext: sealed,
        signingKey: keys.clientSigning,
        encryptingKey: keys.clientEncrypting,
        iv: keys.clientIv,
      ), throwsA(isA<StateError>()));
    });
  });

  group('Frame-size pre-computation', () {
    test('TC-SIZE-001 OPN inner size matches actual ciphertext length', () {
      final policy = Basic256Sha256SecurityPolicy();
      const bodyLen = 100;
      final predicted = Basic256Sha256SecurityPolicy.predictOpnInnerSize(
        sequenceAndBodyLen: bodyLen,
        receiverKeyBytes: 256,
        senderKeyBytes: 256,
      );

      final sealed = policy.signEncryptOpnInner(
        headerContext: Uint8List(28),
        sequenceAndBody: List<int>.generate(bodyLen, (i) => i & 0xFF),
        peerPublicKey: server.publicKey,
        ourPrivateKey: client.privateKey,
      );

      expect(sealed.length, predicted);
    });

    test('TC-SIZE-002 symmetric inner size matches actual ciphertext length',
        () {
      final policy = Basic256Sha256SecurityPolicy();
      final keys = Basic256Sha256SecurityPolicy.deriveChannelKeys(
        clientNonce: List<int>.generate(32, (i) => i),
        serverNonce: List<int>.generate(32, (i) => 32 - i),
      );
      const bodyLen = 100;
      final predicted =
          Basic256Sha256SecurityPolicy.predictSymmetricInnerSize(
              sequenceAndBodyLen: bodyLen);

      final sealed = policy.signEncryptSymmetricInner(
        headerContext: Uint8List(16),
        sequenceAndBody: List<int>.generate(bodyLen, (i) => i & 0xFF),
        signingKey: keys.clientSigning,
        encryptingKey: keys.clientEncrypting,
        iv: keys.clientIv,
      );

      expect(sealed.length, predicted);
    });
  });

  group('Body-only hooks unsupported', () {
    test('TC-HOOK-001 body-only hooks throw UnsupportedError', () {
      final policy = Basic256Sha256SecurityPolicy();
      expect(() => policy.signOutboundOpn([1]),
          throwsA(isA<UnsupportedError>()));
      expect(() => policy.unsealInboundOpn([1]),
          throwsA(isA<UnsupportedError>()));
      expect(() => policy.signOutboundSymmetric([1]),
          throwsA(isA<UnsupportedError>()));
      expect(() => policy.unsealInboundSymmetric([1]),
          throwsA(isA<UnsupportedError>()));
    });
  });
}
