/// PEM / DER key + certificate parsing for OPC UA SecurityPolicy
/// implementations.
///
/// Supports:
///   * RSA private key — PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`)
///     and PKCS#8 (`-----BEGIN PRIVATE KEY-----`) PEM forms, plus
///     the equivalent DER bytes.
///   * X.509 certificate — PEM (`-----BEGIN CERTIFICATE-----`) and
///     DER. Extracts the embedded `RSAPublicKey` for outbound OPN
///     security headers.
///
/// All parsing is pure Dart via pointycastle's `ASN1Parser`; no
/// external bindings or platform libraries are used.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/asn1.dart' as asn1;

import 'rsa.dart';

class KeyParseError implements Exception {
  final String message;
  const KeyParseError(this.message);
  @override
  String toString() => 'KeyParseError: $message';
}

/// Strip the leading `-----BEGIN <kind>-----` / trailing
/// `-----END <kind>-----` markers from a PEM block and base64-decode
/// the inner body. Whitespace inside the body is tolerated.
Uint8List pemDecode(String pem, {String? expectedKind}) {
  final lines = pem
      .split('\n')
      .map((l) => l.trim())
      .where((l) => l.isNotEmpty)
      .toList();
  if (lines.length < 3) {
    throw KeyParseError('PEM too short: $lines');
  }
  final begin = lines.first;
  final end = lines.last;
  if (!begin.startsWith('-----BEGIN ') ||
      !begin.endsWith('-----')) {
    throw KeyParseError('PEM missing BEGIN marker: $begin');
  }
  if (!end.startsWith('-----END ') || !end.endsWith('-----')) {
    throw KeyParseError('PEM missing END marker: $end');
  }
  if (expectedKind != null) {
    final kind = begin.substring(11, begin.length - 5);
    if (kind != expectedKind) {
      throw KeyParseError(
        'PEM kind mismatch — expected "$expectedKind", got "$kind"',
      );
    }
  }
  final body = lines.sublist(1, lines.length - 1).join();
  return base64.decode(body);
}

/// Parse a DER-encoded PKCS#1 `RSAPrivateKey` (RFC 8017 §A.1.2).
///
/// Sequence:
///   version  INTEGER
///   modulus  INTEGER (n)
///   publicExponent INTEGER (e)
///   privateExponent INTEGER (d)
///   prime1   INTEGER (p)
///   prime2   INTEGER (q)
///   exponent1, exponent2, coefficient — ignored here
OpcUaRsaPrivateKey parsePkcs1PrivateKeyDer(List<int> der) {
  final parser = asn1.ASN1Parser(_u8(der));
  final outer = parser.nextObject();
  if (outer is! asn1.ASN1Sequence) {
    throw const KeyParseError('PKCS#1 expected SEQUENCE at top level');
  }
  final children = outer.elements;
  if (children == null || children.length < 6) {
    throw KeyParseError(
      'PKCS#1 SEQUENCE too short (got ${children?.length ?? 0} elements)',
    );
  }
  final n = (children[1] as asn1.ASN1Integer).integer!;
  final d = (children[3] as asn1.ASN1Integer).integer!;
  final p = (children[4] as asn1.ASN1Integer).integer!;
  final q = (children[5] as asn1.ASN1Integer).integer!;
  return OpcUaRsaPrivateKey(n, d, p, q);
}

/// Parse a PEM-encoded PKCS#1 RSA private key. Marker:
/// `-----BEGIN RSA PRIVATE KEY-----`.
OpcUaRsaPrivateKey parsePkcs1PrivateKeyPem(String pem) =>
    parsePkcs1PrivateKeyDer(pemDecode(pem, expectedKind: 'RSA PRIVATE KEY'));

/// Parse a DER-encoded PKCS#8 `PrivateKeyInfo` (RFC 5208) — strips
/// the algorithm identifier wrapper and delegates to
/// [parsePkcs1PrivateKeyDer] on the inner OCTET STRING.
OpcUaRsaPrivateKey parsePkcs8PrivateKeyDer(List<int> der) {
  final parser = asn1.ASN1Parser(_u8(der));
  final outer = parser.nextObject();
  if (outer is! asn1.ASN1Sequence) {
    throw const KeyParseError('PKCS#8 expected SEQUENCE at top level');
  }
  // PrivateKeyInfo := SEQUENCE { version, algorithmIdentifier,
  //                              privateKey OCTET STRING }
  final octet = (outer.elements!)[2] as asn1.ASN1OctetString;
  final inner = octet.octets;
  if (inner == null) {
    throw const KeyParseError(
      'PKCS#8 PrivateKey OCTET STRING is null',
    );
  }
  return parsePkcs1PrivateKeyDer(inner);
}

/// Parse a PEM-encoded PKCS#8 RSA private key. Marker:
/// `-----BEGIN PRIVATE KEY-----`.
OpcUaRsaPrivateKey parsePkcs8PrivateKeyPem(String pem) =>
    parsePkcs8PrivateKeyDer(pemDecode(pem, expectedKind: 'PRIVATE KEY'));

/// Parse a PEM RSA private key — accepts either PKCS#1 or PKCS#8
/// markers (caller doesn't have to know which).
OpcUaRsaPrivateKey parsePrivateKeyPem(String pem) {
  final lines = pem
      .split('\n')
      .map((l) => l.trim())
      .where((l) => l.isNotEmpty);
  for (final line in lines) {
    if (line.startsWith('-----BEGIN RSA PRIVATE KEY-----')) {
      return parsePkcs1PrivateKeyPem(pem);
    }
    if (line.startsWith('-----BEGIN PRIVATE KEY-----')) {
      return parsePkcs8PrivateKeyPem(pem);
    }
    if (line.startsWith('-----BEGIN ')) break;
  }
  throw const KeyParseError(
    'PEM is not a recognised RSA private key form',
  );
}

/// Extract the `RSAPublicKey` (modulus + exponent) from a DER-encoded
/// X.509 v3 certificate.
///
/// Layout (RFC 5280):
///   Certificate ::= SEQUENCE {
///     tbsCertificate       SEQUENCE { ... subjectPublicKeyInfo ... }
///     signatureAlgorithm   AlgorithmIdentifier
///     signatureValue       BIT STRING }
///
/// `subjectPublicKeyInfo` is at index 6 of the tbsCertificate
/// sequence (after version/serial/sigAlg/issuer/validity/subject)
/// — but `version` is optional with `[0]` tag, so we walk children
/// looking for the `SubjectPublicKeyInfo` sequence whose first
/// child is the algorithm identifier OID for rsaEncryption.
OpcUaRsaPublicKey parseX509CertificateRsaPublicKeyDer(List<int> der) {
  final parser = asn1.ASN1Parser(_u8(der));
  final outer = parser.nextObject();
  if (outer is! asn1.ASN1Sequence) {
    throw const KeyParseError('X.509 expected SEQUENCE at top level');
  }
  final tbs = (outer.elements!)[0] as asn1.ASN1Sequence;
  // Walk children, find the SubjectPublicKeyInfo (a SEQUENCE whose
  // first element is itself a SEQUENCE containing an OID).
  for (final child in tbs.elements ?? const <asn1.ASN1Object>[]) {
    if (child is asn1.ASN1Sequence &&
        child.elements != null &&
        child.elements!.length >= 2 &&
        child.elements![0] is asn1.ASN1Sequence &&
        child.elements![1] is asn1.ASN1BitString) {
      final algSeq = child.elements![0] as asn1.ASN1Sequence;
      final algOid = (algSeq.elements!)[0];
      if (algOid is! asn1.ASN1ObjectIdentifier) continue;
      // 1.2.840.113549.1.1.1 = rsaEncryption
      if (algOid.objectIdentifierAsString != '1.2.840.113549.1.1.1') {
        continue;
      }
      final spki = (child.elements![1] as asn1.ASN1BitString).stringValues;
      if (spki == null || spki.isEmpty) {
        throw const KeyParseError(
          'X.509 SubjectPublicKey BIT STRING is empty',
        );
      }
      // The bit string wraps an RSAPublicKey { modulus, exponent }.
      // Drop the leading "unused bits" byte if present (BIT STRING
      // semantics — pointycastle exposes `stringValues` already
      // stripped).
      final inner = asn1.ASN1Parser(Uint8List.fromList(spki));
      final rsa = inner.nextObject() as asn1.ASN1Sequence;
      final n = (rsa.elements![0] as asn1.ASN1Integer).integer!;
      final e = (rsa.elements![1] as asn1.ASN1Integer).integer!;
      return OpcUaRsaPublicKey(n, e);
    }
  }
  throw const KeyParseError(
    'X.509 SubjectPublicKeyInfo (rsaEncryption) not found',
  );
}

/// Parse a PEM-encoded X.509 certificate. Marker:
/// `-----BEGIN CERTIFICATE-----`.
OpcUaRsaPublicKey parseX509CertificatePem(String pem) =>
    parseX509CertificateRsaPublicKeyDer(
        pemDecode(pem, expectedKind: 'CERTIFICATE'));

Uint8List _u8(List<int> b) => b is Uint8List ? b : Uint8List.fromList(b);
