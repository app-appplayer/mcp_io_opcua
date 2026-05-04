/// Pure-Dart crypto primitives wired through `package:pointycastle`,
/// scoped to what OPC UA's Basic256Sha256 (and the broader Aes*
/// family) needs.
///
/// Each helper is intentionally tiny — the goal is a single,
/// auditable surface that the higher-level [OpcUaSecurityPolicy]
/// implementations call into. Testing against published vectors
/// happens here so the policy layer can stay focused on wire
/// layout.
///
/// Algorithms exposed:
///   - SHA-256 hash (digest 32 bytes)
///   - HMAC-SHA-256 (key + msg → 32-byte tag)
///   - AES-CBC encrypt / decrypt (PKCS7 padding optional)
///   - P_SHA256 pseudo-random function (RFC 5246 §5 → OPC UA Part 6
///     §6.7.5)
library;

import 'dart:typed_data';

import 'package:pointycastle/api.dart' as pc;
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/block/modes/cbc.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/paddings/pkcs7.dart';
import 'package:pointycastle/padded_block_cipher/padded_block_cipher_impl.dart';

/// Hash [data] with SHA-256 — returns the 32-byte digest.
Uint8List sha256Digest(List<int> data) {
  final d = SHA256Digest();
  return d.process(_u8(data));
}

/// HMAC-SHA-256 — keyed message authentication.
Uint8List hmacSha256(List<int> key, List<int> message) {
  final mac = HMac(SHA256Digest(), 64) // SHA-256 block size = 64 bytes
    ..init(pc.KeyParameter(_u8(key)));
  return mac.process(_u8(message));
}

/// Encrypt [plaintext] with AES-CBC. When [pkcs7Pad] is `true` the
/// plaintext is padded to a 16-byte block boundary; when `false`
/// the caller must supply already-block-aligned bytes.
Uint8List aesCbcEncrypt({
  required List<int> key,
  required List<int> iv,
  required List<int> plaintext,
  bool pkcs7Pad = true,
}) {
  if (key.length != 16 && key.length != 24 && key.length != 32) {
    throw ArgumentError.value(
        key.length, 'key.length', 'AES key must be 128/192/256 bits');
  }
  if (iv.length != 16) {
    throw ArgumentError.value(iv.length, 'iv.length', 'AES IV is 16 bytes');
  }
  final params = pc.ParametersWithIV<pc.KeyParameter>(
    pc.KeyParameter(_u8(key)), _u8(iv),
  );
  if (pkcs7Pad) {
    final cipher = PaddedBlockCipherImpl(
      PKCS7Padding(),
      CBCBlockCipher(AESEngine()),
    )..init(true, pc.PaddedBlockCipherParameters(params, null));
    return cipher.process(_u8(plaintext));
  }
  if (plaintext.length % 16 != 0) {
    throw ArgumentError(
      'AES-CBC plaintext must be 16-byte aligned when pkcs7Pad is false '
      '(got ${plaintext.length})',
    );
  }
  final cipher = CBCBlockCipher(AESEngine())..init(true, params);
  final out = Uint8List(plaintext.length);
  for (var i = 0; i < plaintext.length; i += 16) {
    cipher.processBlock(_u8(plaintext), i, out, i);
  }
  return out;
}

/// Decrypt [ciphertext] with AES-CBC. When [pkcs7Pad] is `true` the
/// padding is stripped after decryption.
Uint8List aesCbcDecrypt({
  required List<int> key,
  required List<int> iv,
  required List<int> ciphertext,
  bool pkcs7Pad = true,
}) {
  if (ciphertext.length % 16 != 0) {
    throw ArgumentError(
      'AES-CBC ciphertext must be 16-byte aligned (got ${ciphertext.length})',
    );
  }
  final params = pc.ParametersWithIV<pc.KeyParameter>(
    pc.KeyParameter(_u8(key)), _u8(iv),
  );
  if (pkcs7Pad) {
    final cipher = PaddedBlockCipherImpl(
      PKCS7Padding(),
      CBCBlockCipher(AESEngine()),
    )..init(false, pc.PaddedBlockCipherParameters(params, null));
    return cipher.process(_u8(ciphertext));
  }
  final cipher = CBCBlockCipher(AESEngine())..init(false, params);
  final out = Uint8List(ciphertext.length);
  for (var i = 0; i < ciphertext.length; i += 16) {
    cipher.processBlock(_u8(ciphertext), i, out, i);
  }
  return out;
}

/// `P_SHA256` pseudo-random function (RFC 5246 §5 / OPC UA Part 6
/// §6.7.5). Iterates `HMAC_SHA256(secret, A(i) || seed)` until at
/// least [length] bytes have been produced, then truncates to
/// [length].
///
/// `A(0) = seed; A(i) = HMAC(secret, A(i-1))`.
Uint8List pSha256({
  required List<int> secret,
  required List<int> seed,
  required int length,
}) {
  if (length < 0) {
    throw ArgumentError.value(length, 'length', 'must be non-negative');
  }
  final out = BytesBuilder(copy: false);
  var a = _u8(seed);
  while (out.length < length) {
    a = hmacSha256(secret, a);
    final block = hmacSha256(secret, [...a, ...seed]);
    out.add(block);
  }
  return out.toBytes().sublist(0, length);
}

Uint8List _u8(List<int> b) =>
    b is Uint8List ? b : Uint8List.fromList(b);
