/// RSA primitive tests — generate a fresh keypair, exercise OAEP /
/// PKCS1 / PKCS1-v1.5-SHA256 / PSS-SHA256 roundtrips.
@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:pointycastle/api.dart' as pc;
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'package:pointycastle/random/fortuna_random.dart';
import 'package:test/test.dart';

pc.AsymmetricKeyPair<OpcUaRsaPublicKey, OpcUaRsaPrivateKey> _genKeyPair({
  int bits = 2048,
}) {
  final rnd = FortunaRandom();
  // Seed Fortuna with a fixed-but-good-enough seed for tests so the
  // suite is deterministic.
  rnd.seed(pc.KeyParameter(
      Uint8List.fromList(List<int>.generate(32, (i) => i + 1))));
  final gen = RSAKeyGenerator()
    ..init(pc.ParametersWithRandom(
      RSAKeyGeneratorParameters(BigInt.parse('65537'), bits, 64),
      rnd,
    ));
  final pair = gen.generateKeyPair();
  return pc.AsymmetricKeyPair<OpcUaRsaPublicKey, OpcUaRsaPrivateKey>(
    pair.publicKey as OpcUaRsaPublicKey,
    pair.privateKey as OpcUaRsaPrivateKey,
  );
}

void main() {
  late pc.AsymmetricKeyPair<OpcUaRsaPublicKey, OpcUaRsaPrivateKey> keys;
  setUpAll(() {
    keys = _genKeyPair();
  });

  group('RSA-OAEP', () {
    test('TC-RSA-001 OAEP-SHA1 encrypt+decrypt roundtrip (Basic256Sha256)',
        () {
      final pt = 'opc-ua-secret-payload-bytes'.codeUnits;
      final ct = rsaOaepEncrypt(publicKey: keys.publicKey, plaintext: pt);
      // 2048-bit key → 256-byte block.
      expect(ct.length, 256);
      final back = rsaOaepDecrypt(privateKey: keys.privateKey, ciphertext: ct);
      expect(back, pt);
    });

    test('TC-RSA-002 OAEP-SHA256 encrypt+decrypt roundtrip '
        '(Aes128_Sha256_RsaOaep)', () {
      final pt = List<int>.generate(64, (i) => i);
      final ct = rsaOaepEncrypt(
        publicKey: keys.publicKey, plaintext: pt, useSha256: true,
      );
      final back = rsaOaepDecrypt(
        privateKey: keys.privateKey, ciphertext: ct, useSha256: true,
      );
      expect(back, pt);
    });
  });

  group('RSA-PKCS1', () {
    test('TC-RSA-003 PKCS1 encrypt+decrypt roundtrip (Basic128Rsa15)', () {
      final pt = 'short payload'.codeUnits;
      final ct = rsaPkcs1Encrypt(publicKey: keys.publicKey, plaintext: pt);
      final back =
          rsaPkcs1Decrypt(privateKey: keys.privateKey, ciphertext: ct);
      expect(back, pt);
    });
  });

  group('RSA-PKCS1-v1.5-SHA256 sign/verify', () {
    test('TC-RSA-004 sign + verify roundtrip', () {
      final msg = 'OPC UA OPN body'.codeUnits;
      final sig = rsaPkcs1Sha256Sign(
          privateKey: keys.privateKey, message: msg);
      expect(rsaPkcs1Sha256Verify(
        publicKey: keys.publicKey, message: msg, signature: sig,
      ), isTrue);
    });

    test('TC-RSA-005 verify fails on tampered message', () {
      final msg = 'OPC UA OPN body'.codeUnits;
      final sig = rsaPkcs1Sha256Sign(
          privateKey: keys.privateKey, message: msg);
      final tampered = [...msg]..[0] ^= 0x01;
      expect(rsaPkcs1Sha256Verify(
        publicKey: keys.publicKey, message: tampered, signature: sig,
      ), isFalse);
    });
  });

  group('RSA-PSS-SHA256 sign/verify (Aes256_Sha256_RsaPss)', () {
    test('TC-RSA-006 sign + verify roundtrip', () {
      final msg = 'pss-protected'.codeUnits;
      final sig = rsaPssSha256Sign(
          privateKey: keys.privateKey, message: msg);
      expect(rsaPssSha256Verify(
        publicKey: keys.publicKey, message: msg, signature: sig,
      ), isTrue);
    });

    test('TC-RSA-007 verify fails on tampered signature', () {
      final msg = 'pss-protected'.codeUnits;
      final sig = rsaPssSha256Sign(
          privateKey: keys.privateKey, message: msg);
      sig[0] ^= 0xFF;
      expect(rsaPssSha256Verify(
        publicKey: keys.publicKey, message: msg, signature: sig,
      ), isFalse);
    });
  });

  group('Type aliases', () {
    test('TC-RSA-008 OpcUaRsaPublicKey is pointycastle RSAPublicKey', () {
      expect(keys.publicKey, isA<RSAPublicKey>());
    });
  });
}
