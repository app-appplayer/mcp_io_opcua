/// Roundtrip tests for `Aes128_Sha256_RsaOaep` and
/// `Aes256_Sha256_RsaPss` security policies — Part 7 §6.1.4 / §6.1.5.
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
    client = _genKeyPair(31);
    server = _genKeyPair(41);
  });

  group('Aes128_Sha256_RsaOaep', () {
    test('TC-AES128-001 OPN sign+encrypt roundtrip', () {
      final clientPolicy = Aes128Sha256RsaOaepSecurityPolicy(
        ownPrivateKey: client.privateKey,
        peerPublicKey: server.publicKey,
        isClient: true,
      );
      final serverPolicy = Aes128Sha256RsaOaepSecurityPolicy(
        ownPrivateKey: server.privateKey,
        peerPublicKey: client.publicKey,
        isClient: false,
      );
      final body = List<int>.generate(96, (i) => i & 0xFF);
      final ctx = Uint8List(28);

      final sealed = clientPolicy.signEncryptOpn(
        headerContext: ctx,
        sequenceAndBody: body,
      );
      final recovered = serverPolicy.verifyDecryptOpn(
        headerContext: ctx,
        ciphertext: sealed,
      );
      expect(recovered, body);
    });

    test('TC-AES128-002 KDF yields 32+16+16 layout (AES-128)', () {
      final p = Aes128Sha256RsaOaepSecurityPolicy();
      final keys = p.deriveChannelKeys(
        clientNonce: List<int>.generate(32, (i) => i),
        serverNonce: List<int>.generate(32, (i) => 32 - i),
      );
      expect(keys.clientSigning.length, 32);
      expect(keys.clientEncrypting.length, 16); // AES-128
      expect(keys.clientIv.length, 16);
    });

    test('TC-AES128-003 symmetric MSG roundtrip after bindChannelKeys',
        () {
      final p = Aes128Sha256RsaOaepSecurityPolicy(
        ownPrivateKey: client.privateKey,
        peerPublicKey: server.publicKey,
      );
      final keys = p.deriveChannelKeys(
        clientNonce: List<int>.generate(32, (i) => i),
        serverNonce: List<int>.generate(32, (i) => 32 - i),
      );
      final clientSide = Aes128Sha256RsaOaepSecurityPolicy(
        ownPrivateKey: client.privateKey,
        peerPublicKey: server.publicKey,
        isClient: true,
      )..bindChannelKeys(keys);
      final serverSide = Aes128Sha256RsaOaepSecurityPolicy(
        ownPrivateKey: server.privateKey,
        peerPublicKey: client.publicKey,
        isClient: false,
      )..bindChannelKeys(keys);

      final body = List<int>.generate(80, (i) => (i * 5) & 0xFF);
      final sealed = clientSide.signEncryptSymmetric(
        headerContext: Uint8List(16),
        sequenceAndBody: body,
      );
      final recovered = serverSide.verifyDecryptSymmetric(
        headerContext: Uint8List(16),
        ciphertext: sealed,
      );
      expect(recovered, body);
    });
  });

  group('Aes256_Sha256_RsaPss', () {
    test('TC-AES256PSS-001 OPN sign+encrypt roundtrip', () {
      final clientPolicy = Aes256Sha256RsaPssSecurityPolicy(
        ownPrivateKey: client.privateKey,
        peerPublicKey: server.publicKey,
        isClient: true,
      );
      final serverPolicy = Aes256Sha256RsaPssSecurityPolicy(
        ownPrivateKey: server.privateKey,
        peerPublicKey: client.publicKey,
        isClient: false,
      );
      final body = List<int>.generate(96, (i) => i & 0xFF);
      final ctx = Uint8List(28);

      final sealed = clientPolicy.signEncryptOpn(
        headerContext: ctx,
        sequenceAndBody: body,
      );
      final recovered = serverPolicy.verifyDecryptOpn(
        headerContext: ctx,
        ciphertext: sealed,
      );
      expect(recovered, body);
    });

    test('TC-AES256PSS-002 KDF yields 32+32+16 layout (AES-256)', () {
      final p = Aes256Sha256RsaPssSecurityPolicy();
      final keys = p.deriveChannelKeys(
        clientNonce: List<int>.generate(32, (i) => i),
        serverNonce: List<int>.generate(32, (i) => 32 - i),
      );
      expect(keys.clientSigning.length, 32);
      expect(keys.clientEncrypting.length, 32); // AES-256
      expect(keys.clientIv.length, 16);
    });

    test('TC-AES256PSS-003 tampered ciphertext rejected', () {
      final clientPolicy = Aes256Sha256RsaPssSecurityPolicy(
        ownPrivateKey: client.privateKey,
        peerPublicKey: server.publicKey,
        isClient: true,
      );
      final serverPolicy = Aes256Sha256RsaPssSecurityPolicy(
        ownPrivateKey: server.privateKey,
        peerPublicKey: client.publicKey,
        isClient: false,
      );
      final body = List<int>.generate(64, (i) => i & 0xFF);
      final ctx = Uint8List(28);
      final sealed = clientPolicy.signEncryptOpn(
        headerContext: ctx,
        sequenceAndBody: body,
      );
      final tampered = Uint8List.fromList(sealed)..[20] ^= 0x01;
      expect(
        () => serverPolicy.verifyDecryptOpn(
          headerContext: ctx,
          ciphertext: tampered,
        ),
        throwsA(anything),
      );
    });
  });
}
