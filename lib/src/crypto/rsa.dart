/// RSA primitives needed by the OPC UA Basic256Sha256 / Aes128_Sha256
/// / Aes256_Sha256 security policies — encrypt with RSA-OAEP-SHA1 (or
/// SHA-256 for Aes*-policies), sign with RSA-PSS-SHA-256 or
/// RSA-PKCS1-v1_5-SHA-256, and the inverse decrypt / verify.
///
/// All key types are pointycastle's `RSAPrivateKey` / `RSAPublicKey`.
/// Key parsing from DER / PEM lives separately in `key_parsing.dart`.
library;

import 'dart:math' as math;
import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart' as pc;
import 'package:pointycastle/pointycastle.dart'
    show
        RSAPublicKey,
        RSAPrivateKey,
        RSASignature,
        PSSSignature,
        ParametersWithSaltConfiguration;
import 'package:pointycastle/asymmetric/oaep.dart';
import 'package:pointycastle/asymmetric/pkcs1.dart';
import 'package:pointycastle/asymmetric/rsa.dart';
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/random/fortuna_random.dart';
import 'package:pointycastle/signers/pss_signer.dart';
import 'package:pointycastle/signers/rsa_signer.dart';

/// Pointycastle's `RSAPublicKey` re-export — callers don't have to
/// import pointycastle directly.
typedef OpcUaRsaPublicKey = RSAPublicKey;
typedef OpcUaRsaPrivateKey = RSAPrivateKey;

/// RSA-OAEP-SHA1 encrypt — Basic256Sha256 / Basic256 use SHA-1 in
/// the OAEP mask generation function (per OPC UA Part 7 §6.1.3).
/// Aes128/256_Sha256_RsaOaep policies use SHA-256 — pass
/// `useSha256: true`.
Uint8List rsaOaepEncrypt({
  required OpcUaRsaPublicKey publicKey,
  required List<int> plaintext,
  bool useSha256 = false,
}) {
  final cipher = OAEPEncoding.withCustomDigest(
    () => useSha256 ? SHA256Digest() : SHA1Digest(),
    RSAEngine(),
  )..init(true, pc.PublicKeyParameter<OpcUaRsaPublicKey>(publicKey));
  return cipher.process(_u8(plaintext));
}

/// RSA-OAEP decrypt — inverse of [rsaOaepEncrypt].
Uint8List rsaOaepDecrypt({
  required OpcUaRsaPrivateKey privateKey,
  required List<int> ciphertext,
  bool useSha256 = false,
}) {
  final cipher = OAEPEncoding.withCustomDigest(
    () => useSha256 ? SHA256Digest() : SHA1Digest(),
    RSAEngine(),
  )..init(false, pc.PrivateKeyParameter<OpcUaRsaPrivateKey>(privateKey));
  return cipher.process(_u8(ciphertext));
}

/// RSA-PKCS1-v1.5 sign with SHA-256 — Basic256Sha256 uses this for
/// the asymmetric signature in OPN.
Uint8List rsaPkcs1Sha256Sign({
  required OpcUaRsaPrivateKey privateKey,
  required List<int> message,
}) {
  final signer = RSASigner(SHA256Digest(), '0609608648016503040201')
    ..init(true, pc.PrivateKeyParameter<OpcUaRsaPrivateKey>(privateKey));
  return signer.generateSignature(_u8(message)).bytes;
}

/// RSA-PKCS1-v1.5 verify with SHA-256. Returns `false` on any
/// verification failure (including pointycastle throws on bad
/// padding).
bool rsaPkcs1Sha256Verify({
  required OpcUaRsaPublicKey publicKey,
  required List<int> message,
  required List<int> signature,
}) {
  final verifier = RSASigner(SHA256Digest(), '0609608648016503040201')
    ..init(false, pc.PublicKeyParameter<OpcUaRsaPublicKey>(publicKey));
  try {
    return verifier.verifySignature(
      _u8(message),
      RSASignature(_u8(signature)),
    );
  } on Object {
    return false;
  }
}

/// RSA-PSS sign with SHA-256 — Aes256_Sha256_RsaPss uses this.
/// Salt source: caller-supplied [random], else `dart:math Random.secure`
/// seed → Fortuna RNG (pointycastle's stream cipher CSPRNG).
Uint8List rsaPssSha256Sign({
  required OpcUaRsaPrivateKey privateKey,
  required List<int> message,
  int saltLength = 32,
  pc.SecureRandom? random,
}) {
  final signer = PSSSigner(RSAEngine(), SHA256Digest(), SHA256Digest());
  final rnd = random ?? _secureRandom();
  final params = ParametersWithSaltConfiguration<
      pc.PrivateKeyParameter<OpcUaRsaPrivateKey>>(
    pc.PrivateKeyParameter<OpcUaRsaPrivateKey>(privateKey),
    rnd,
    saltLength,
  );
  signer.init(true, params);
  return signer.generateSignature(_u8(message)).bytes;
}

/// Build a freshly-seeded Fortuna CSPRNG. Pure-Dart so this works
/// on every supported target (web included via `dart:math` fallback;
/// VM uses OS entropy via `Random.secure()`).
pc.SecureRandom _secureRandom() {
  final seed = Uint8List(32);
  final rnd = math.Random.secure();
  for (var i = 0; i < seed.length; i++) {
    seed[i] = rnd.nextInt(256);
  }
  return FortunaRandom()..seed(pc.KeyParameter(seed));
}

/// RSA-PSS verify with SHA-256. Verification ignores the supplied
/// salt bytes — the algorithm recovers them from the encoded
/// message (RFC 3447 §9.1.2). Hence the `Configuration` variant.
///
/// Returns `false` on any verification failure, including when
/// `RSAEngine.process` throws because the tampered signature does
/// not decrypt cleanly.
bool rsaPssSha256Verify({
  required OpcUaRsaPublicKey publicKey,
  required List<int> message,
  required List<int> signature,
  int saltLength = 32,
}) {
  final signer = PSSSigner(RSAEngine(), SHA256Digest(), SHA256Digest());
  final params = ParametersWithSaltConfiguration<
      pc.PublicKeyParameter<OpcUaRsaPublicKey>>(
    pc.PublicKeyParameter<OpcUaRsaPublicKey>(publicKey),
    _secureRandom(),
    saltLength,
  );
  signer.init(false, params);
  try {
    return signer.verifySignature(
      _u8(message),
      PSSSignature(_u8(signature)),
    );
  } on Object {
    return false;
  }
}

/// PKCS1 (RSAES-PKCS1-v1_5) encrypt — Basic128Rsa15 uses this.
Uint8List rsaPkcs1Encrypt({
  required OpcUaRsaPublicKey publicKey,
  required List<int> plaintext,
}) {
  final cipher = PKCS1Encoding(RSAEngine())
    ..init(true, pc.PublicKeyParameter<OpcUaRsaPublicKey>(publicKey));
  return cipher.process(_u8(plaintext));
}

/// PKCS1 decrypt.
Uint8List rsaPkcs1Decrypt({
  required OpcUaRsaPrivateKey privateKey,
  required List<int> ciphertext,
}) {
  final cipher = PKCS1Encoding(RSAEngine())
    ..init(false, pc.PrivateKeyParameter<OpcUaRsaPrivateKey>(privateKey));
  return cipher.process(_u8(ciphertext));
}

Uint8List _u8(List<int> b) => b is Uint8List ? b : Uint8List.fromList(b);
