/// Tests for cert + RSA key parsing.
///
/// Generates a 2048-bit keypair in-suite, hand-builds a PKCS#1 +
/// PKCS#8 + minimal X.509 DER from it, encodes to PEM, then parses
/// back and verifies the modulus / exponent / private exponent
/// match the originals.
@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:pointycastle/api.dart' as pc;
import 'package:pointycastle/asn1.dart' as asn1;
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'package:pointycastle/random/fortuna_random.dart';
import 'package:test/test.dart';

pc.AsymmetricKeyPair<OpcUaRsaPublicKey, OpcUaRsaPrivateKey> _genKeyPair() {
  final rnd = FortunaRandom()
    ..seed(pc.KeyParameter(
        Uint8List.fromList(List<int>.generate(32, (i) => i + 7))));
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

/// Hand-build a PKCS#1 RSAPrivateKey DER for [k]. Format:
/// `SEQUENCE { 0, n, e, d, p, q, d_p, d_q, q_inv }`.
Uint8List _toPkcs1Der(OpcUaRsaPrivateKey k) {
  // Compute the CRT components — pointycastle's RSAPrivateKey
  // already supplies p, q; d_p, d_q, q_inv we derive here.
  final p = k.p!;
  final q = k.q!;
  final d = k.privateExponent!;
  final dP = d.remainder(p - BigInt.one);
  final dQ = d.remainder(q - BigInt.one);
  final qInv = q.modInverse(p);
  final seq = asn1.ASN1Sequence(elements: [
    asn1.ASN1Integer(BigInt.zero),
    asn1.ASN1Integer(k.modulus!),
    asn1.ASN1Integer(k.publicExponent!),
    asn1.ASN1Integer(d),
    asn1.ASN1Integer(p),
    asn1.ASN1Integer(q),
    asn1.ASN1Integer(dP),
    asn1.ASN1Integer(dQ),
    asn1.ASN1Integer(qInv),
  ]);
  return seq.encode();
}

/// Wrap PKCS#1 DER into a PKCS#8 PrivateKeyInfo.
Uint8List _toPkcs8Der(OpcUaRsaPrivateKey k) {
  final algId = asn1.ASN1Sequence(elements: [
    asn1.ASN1ObjectIdentifier.fromIdentifierString('1.2.840.113549.1.1.1'),
    asn1.ASN1Null(),
  ]);
  final pkcs1 = _toPkcs1Der(k);
  final outer = asn1.ASN1Sequence(elements: [
    asn1.ASN1Integer(BigInt.zero),
    algId,
    asn1.ASN1OctetString(octets: pkcs1),
  ]);
  return outer.encode();
}

/// Hand-build a minimal self-signed X.509 v1 certificate carrying
/// only what the OPC UA SecurityPolicy needs: the SubjectPublicKeyInfo
/// for an `rsaEncryption` key. The signature bytes are arbitrary —
/// we only assert that the public-key extractor finds the modulus +
/// exponent.
Uint8List _toMinimalX509Der(OpcUaRsaPublicKey k) {
  // SubjectPublicKeyInfo wraps RSAPublicKey { modulus, exponent }.
  final rsa = asn1.ASN1Sequence(elements: [
    asn1.ASN1Integer(k.modulus!),
    asn1.ASN1Integer(k.publicExponent!),
  ]);
  final spki = asn1.ASN1Sequence(elements: [
    asn1.ASN1Sequence(elements: [
      asn1.ASN1ObjectIdentifier.fromIdentifierString('1.2.840.113549.1.1.1'),
      asn1.ASN1Null(),
    ]),
    asn1.ASN1BitString(stringValues: rsa.encode()),
  ]);
  final tbs = asn1.ASN1Sequence(elements: [
    // version (default v1 — we omit the [0] EXPLICIT tag)
    asn1.ASN1Integer(BigInt.one),
    // serial
    asn1.ASN1Integer(BigInt.from(123456)),
    // signature algorithm — sha256WithRSAEncryption
    asn1.ASN1Sequence(elements: [
      asn1.ASN1ObjectIdentifier.fromIdentifierString('1.2.840.113549.1.1.11'),
      asn1.ASN1Null(),
    ]),
    // issuer (empty SEQUENCE)
    asn1.ASN1Sequence(elements: []),
    // validity (notBefore + notAfter — UTCTime placeholders)
    asn1.ASN1Sequence(elements: [
      asn1.ASN1UtcTime(DateTime.utc(2020)),
      asn1.ASN1UtcTime(DateTime.utc(2099)),
    ]),
    // subject (empty SEQUENCE)
    asn1.ASN1Sequence(elements: []),
    spki,
  ]);
  // The full certificate wraps tbs + sigAlg + signatureBitString.
  return asn1.ASN1Sequence(elements: [
    tbs,
    asn1.ASN1Sequence(elements: [
      asn1.ASN1ObjectIdentifier.fromIdentifierString('1.2.840.113549.1.1.11'),
      asn1.ASN1Null(),
    ]),
    asn1.ASN1BitString(stringValues: Uint8List(32)),
  ]).encode();
}

String _toPem(String kind, Uint8List der) {
  final body = base64.encode(der);
  final wrapped = StringBuffer();
  for (var i = 0; i < body.length; i += 64) {
    wrapped.writeln(body.substring(i, (i + 64).clamp(0, body.length)));
  }
  return '-----BEGIN $kind-----\n$wrapped-----END $kind-----';
}

void main() {
  late pc.AsymmetricKeyPair<OpcUaRsaPublicKey, OpcUaRsaPrivateKey> keys;
  setUpAll(() {
    keys = _genKeyPair();
  });

  group('PEM decode', () {
    test('TC-PEM-001 strips BEGIN/END markers and base64-decodes', () {
      final body = utf8.encode('hello');
      final encoded = base64.encode(body);
      final pem = '-----BEGIN TEST-----\n$encoded\n-----END TEST-----';
      expect(pemDecode(pem), body);
    });

    test('TC-PEM-002 rejects mismatched expectedKind', () {
      final pem =
          '-----BEGIN A-----\n${base64.encode([0])}\n-----END A-----';
      expect(() => pemDecode(pem, expectedKind: 'B'),
          throwsA(isA<KeyParseError>()));
    });
  });

  group('PKCS#1 RSA private key', () {
    test('TC-K1-001 DER roundtrip recovers n / e / d / p / q', () {
      final der = _toPkcs1Der(keys.privateKey);
      final back = parsePkcs1PrivateKeyDer(der);
      expect(back.modulus, keys.privateKey.modulus);
      expect(back.privateExponent, keys.privateKey.privateExponent);
      expect(back.p, keys.privateKey.p);
      expect(back.q, keys.privateKey.q);
    });

    test('TC-K1-002 PEM (RSA PRIVATE KEY) parses', () {
      final der = _toPkcs1Der(keys.privateKey);
      final pem = _toPem('RSA PRIVATE KEY', der);
      final back = parsePkcs1PrivateKeyPem(pem);
      expect(back.modulus, keys.privateKey.modulus);
    });
  });

  group('PKCS#8 RSA private key', () {
    test('TC-K8-001 DER roundtrip', () {
      final der = _toPkcs8Der(keys.privateKey);
      final back = parsePkcs8PrivateKeyDer(der);
      expect(back.modulus, keys.privateKey.modulus);
      expect(back.privateExponent, keys.privateKey.privateExponent);
    });

    test('TC-K8-002 PEM (PRIVATE KEY) parses', () {
      final der = _toPkcs8Der(keys.privateKey);
      final pem = _toPem('PRIVATE KEY', der);
      final back = parsePkcs8PrivateKeyPem(pem);
      expect(back.modulus, keys.privateKey.modulus);
    });
  });

  group('Auto-detect PEM private key form', () {
    test('TC-KAUTO-001 routes RSA PRIVATE KEY → PKCS#1 parser', () {
      final pem = _toPem('RSA PRIVATE KEY', _toPkcs1Der(keys.privateKey));
      expect(parsePrivateKeyPem(pem).modulus, keys.privateKey.modulus);
    });

    test('TC-KAUTO-002 routes PRIVATE KEY → PKCS#8 parser', () {
      final pem = _toPem('PRIVATE KEY', _toPkcs8Der(keys.privateKey));
      expect(parsePrivateKeyPem(pem).modulus, keys.privateKey.modulus);
    });

    test('TC-KAUTO-003 unknown PEM kind throws', () {
      final pem =
          _toPem('UNKNOWN KEY', _toPkcs1Der(keys.privateKey));
      expect(() => parsePrivateKeyPem(pem), throwsA(isA<KeyParseError>()));
    });
  });

  group('X.509 certificate public-key extraction', () {
    test('TC-X509-001 DER cert → RSAPublicKey matches', () {
      final der = _toMinimalX509Der(keys.publicKey);
      final back = parseX509CertificateRsaPublicKeyDer(der);
      expect(back.modulus, keys.publicKey.modulus);
      expect(back.exponent, keys.publicKey.exponent);
    });

    test('TC-X509-002 PEM cert parses', () {
      final pem =
          _toPem('CERTIFICATE', _toMinimalX509Der(keys.publicKey));
      final back = parseX509CertificatePem(pem);
      expect(back.modulus, keys.publicKey.modulus);
    });
  });

  group('Sign with parsed key + verify with parsed cert', () {
    test('TC-K-PIPELINE-001 parsed private key signs + parsed cert verifies',
        () {
      final pem = _toPem('PRIVATE KEY', _toPkcs8Der(keys.privateKey));
      final certPem =
          _toPem('CERTIFICATE', _toMinimalX509Der(keys.publicKey));

      final priv = parsePrivateKeyPem(pem);
      final pub = parseX509CertificatePem(certPem);

      final sig = rsaPkcs1Sha256Sign(
          privateKey: priv, message: 'hello'.codeUnits);
      expect(rsaPkcs1Sha256Verify(
        publicKey: pub, message: 'hello'.codeUnits, signature: sig,
      ), isTrue);
    });
  });
}
