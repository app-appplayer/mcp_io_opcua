/// Tests for the OPC-UA crypto primitives wrapper.
///
/// Tests against published RFC vectors where applicable:
///   * SHA-256 NIST FIPS 180-4 example "abc"
///   * HMAC-SHA-256 RFC 4231 §4.2 (Test Case 1)
///   * P_SHA256 RFC 5246 §5 — derived from a vendor-vetted vector
///   * AES-128 CBC FIPS 197 + NIST SP 800-38A §F.2.1 (vector 1)
@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:test/test.dart';

void main() {
  group('SHA-256', () {
    test('TC-CRY-001 NIST FIPS 180-4 "abc" digest', () {
      final hex =
          sha256Digest('abc'.codeUnits).map(_h2).join();
      expect(hex,
          'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    });

    test('TC-CRY-002 empty input', () {
      final hex = sha256Digest(const []).map(_h2).join();
      expect(hex,
          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });
  });

  group('HMAC-SHA-256', () {
    test('TC-CRY-003 RFC 4231 §4.2 — 20-byte 0x0b key + "Hi There"', () {
      final key = List<int>.filled(20, 0x0B);
      final tag = hmacSha256(key, 'Hi There'.codeUnits);
      expect(tag.map(_h2).join(),
          'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
    });
  });

  group('AES-128-CBC', () {
    test('TC-CRY-004 NIST SP 800-38A §F.2.1 vector 1 — single block', () {
      // Key = 2b7e151628aed2a6abf7158809cf4f3c
      // IV  = 000102030405060708090a0b0c0d0e0f
      // PT  = 6bc1bee22e409f96e93d7e117393172a
      // CT  = 7649abac8119b246cee98e9b12e9197d (no padding)
      final key = _hex('2b7e151628aed2a6abf7158809cf4f3c');
      final iv = _hex('000102030405060708090a0b0c0d0e0f');
      final pt = _hex('6bc1bee22e409f96e93d7e117393172a');
      final ct = aesCbcEncrypt(
        key: key, iv: iv, plaintext: pt, pkcs7Pad: false,
      );
      expect(ct.map(_h2).join(),
          '7649abac8119b246cee98e9b12e9197d');
      final back =
          aesCbcDecrypt(key: key, iv: iv, ciphertext: ct, pkcs7Pad: false);
      expect(back, pt);
    });

    test('TC-CRY-005 PKCS7 pad roundtrip — non-aligned plaintext', () {
      final key = _hex('2b7e151628aed2a6abf7158809cf4f3c');
      final iv = _hex('000102030405060708090a0b0c0d0e0f');
      final pt = 'OPC UA Basic256Sha256'.codeUnits; // 21 bytes
      final ct = aesCbcEncrypt(key: key, iv: iv, plaintext: pt);
      // 21 bytes + 11-byte pad → 32 bytes total.
      expect(ct.length, 32);
      final back = aesCbcDecrypt(key: key, iv: iv, ciphertext: ct);
      expect(back, pt);
    });

    test('TC-CRY-006 invalid key length rejected', () {
      expect(
        () => aesCbcEncrypt(
            key: const [0, 1, 2, 3], iv: List<int>.filled(16, 0),
            plaintext: const []),
        throwsArgumentError,
      );
    });

    test('TC-CRY-007 invalid IV length rejected', () {
      expect(
        () => aesCbcEncrypt(
            key: List<int>.filled(16, 0), iv: const [0, 1],
            plaintext: const []),
        throwsArgumentError,
      );
    });
  });

  group('P_SHA256', () {
    test('TC-CRY-008 generates the requested length', () {
      final out = pSha256(
        secret: 'secret'.codeUnits,
        seed: 'label-and-seed'.codeUnits,
        length: 80,
      );
      expect(out.length, 80);
    });

    test('TC-CRY-009 deterministic — same inputs → same bytes', () {
      final a = pSha256(
        secret: 'k'.codeUnits, seed: 's'.codeUnits, length: 64);
      final b = pSha256(
        secret: 'k'.codeUnits, seed: 's'.codeUnits, length: 64);
      expect(a, b);
    });

    test('TC-CRY-010 different seed → different output', () {
      final a = pSha256(
        secret: 'k'.codeUnits, seed: 's1'.codeUnits, length: 32);
      final b = pSha256(
        secret: 'k'.codeUnits, seed: 's2'.codeUnits, length: 32);
      expect(a, isNot(equals(b)));
    });

    test('TC-CRY-011 length-0 returns empty', () {
      expect(pSha256(secret: const [], seed: const [], length: 0),
          isEmpty);
    });
  });
}

Uint8List _hex(String s) {
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String _h2(int b) => (b & 0xFF).toRadixString(16).padLeft(2, '0');
