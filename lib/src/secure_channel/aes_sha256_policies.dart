/// `Aes128_Sha256_RsaOaep` and `Aes256_Sha256_RsaPss` security
/// policies per OPC UA Part 7 §6.1.4 / §6.1.5.
///
/// Both share the Part 6 §6.7 framing semantics with `Basic256Sha256`
/// — header-context-aware sign+encrypt, `predict*InnerSize` for the
/// pre-encryption byte count, channel-key derivation from OPN
/// nonces — but differ on the cipher suite:
///
/// | Policy            | AES key | RSA-OAEP digest | RSA sign      |
/// |-------------------|---------|-----------------|---------------|
/// | Aes128_Sha256_RsaOaep | 128 (16 B) | SHA-256       | PKCS1-v1.5-SHA256 |
/// | Aes256_Sha256_RsaPss  | 256 (32 B) | SHA-256       | PSS-SHA256        |
///
/// Implementation factors out a `_AesSha256PolicyBase` that holds the
/// per-suite parameters; the two concrete classes only set those
/// parameters and route the asymmetric sign/verify call to the
/// matching primitive (PKCS1-v1.5 vs PSS).
library;

import 'dart:typed_data';

import '../crypto/primitives.dart';
import '../crypto/rsa.dart';
import 'security_policy.dart';

/// Bundled symmetric channel keys derived from OPN nonces. Same
/// shape as `Basic256Sha256ChannelKeys`; kept distinct only because
/// the byte lengths differ for the AES-128 policy.
class AesSha256ChannelKeys {
  final Uint8List clientSigning;
  final Uint8List clientEncrypting;
  final Uint8List clientIv;
  final Uint8List serverSigning;
  final Uint8List serverEncrypting;
  final Uint8List serverIv;

  const AesSha256ChannelKeys({
    required this.clientSigning,
    required this.clientEncrypting,
    required this.clientIv,
    required this.serverSigning,
    required this.serverEncrypting,
    required this.serverIv,
  });
}

abstract class _AesSha256PolicyBase extends CryptoSecurityPolicy {
  _AesSha256PolicyBase({
    required super.policyUri,
    required this.symEncryptingKeySize,
    required this.rsaOaepDigestOverhead,
    this.ownPrivateKey,
    this.peerPublicKey,
    this.isClient = true,
    this.channelKeys,
  });

  /// HMAC-SHA-256 output size — same for both policies.
  static const int symSignatureSize = 32;

  /// AES block size — 16 bytes for both AES-128 and AES-256.
  static const int symBlockSize = 16;

  /// AES key size in bytes (16 for AES-128, 32 for AES-256).
  final int symEncryptingKeySize;

  /// `2 * digestSize + 2` overhead for RSA-OAEP (66 bytes for both
  /// policies — they use SHA-256 in OAEP).
  final int rsaOaepDigestOverhead;

  final OpcUaRsaPrivateKey? ownPrivateKey;
  final OpcUaRsaPublicKey? peerPublicKey;
  final bool isClient;
  AesSha256ChannelKeys? channelKeys;

  // ----- Asymmetric sign/verify hooks (per-policy override) --------

  Uint8List _signAsymmetric(
      OpcUaRsaPrivateKey privateKey, List<int> message);
  bool _verifyAsymmetric(
      OpcUaRsaPublicKey publicKey, List<int> message, List<int> signature);

  // ----- Binding helper --------------------------------------------

  void bindChannelKeys(AesSha256ChannelKeys keys) {
    channelKeys = keys;
  }

  // ----- Body-only hooks unsupported -------------------------------

  @override
  Uint8List signOutboundOpn(List<int> body) => throw UnsupportedError(
      '$runtimeType: use header-context signEncryptOpn');
  @override
  Uint8List unsealInboundOpn(List<int> body) => throw UnsupportedError(
      '$runtimeType: use header-context verifyDecryptOpn');
  @override
  Uint8List signOutboundSymmetric(List<int> body) => throw UnsupportedError(
      '$runtimeType: use header-context signEncryptSymmetric');
  @override
  Uint8List unsealInboundSymmetric(List<int> body) => throw UnsupportedError(
      '$runtimeType: use header-context verifyDecryptSymmetric');

  // ----- Channel-key derivation ------------------------------------

  /// Derive channel keys per Part 6 §6.7.5: P_SHA256 of nonces, sliced
  /// into `signing(32) || encrypting(symEncryptingKeySize) || iv(16)`.
  AesSha256ChannelKeys deriveChannelKeys({
    required List<int> clientNonce,
    required List<int> serverNonce,
  }) {
    final total = symSignatureSize + symEncryptingKeySize + symBlockSize;
    final c = pSha256(secret: serverNonce, seed: clientNonce, length: total);
    final s = pSha256(secret: clientNonce, seed: serverNonce, length: total);
    Uint8List slice(Uint8List src, int from, int to) =>
        Uint8List.fromList(src.sublist(from, to));
    return AesSha256ChannelKeys(
      clientSigning: slice(c, 0, symSignatureSize),
      clientEncrypting:
          slice(c, symSignatureSize, symSignatureSize + symEncryptingKeySize),
      clientIv: slice(c, symSignatureSize + symEncryptingKeySize, total),
      serverSigning: slice(s, 0, symSignatureSize),
      serverEncrypting:
          slice(s, symSignatureSize, symSignatureSize + symEncryptingKeySize),
      serverIv: slice(s, symSignatureSize + symEncryptingKeySize, total),
    );
  }

  // ----- Frame-size pre-computation --------------------------------

  int predictOpnInnerBytes({
    required int sequenceAndBodyLen,
    required int receiverKeyBytes,
    required int senderKeyBytes,
  }) {
    final plainBlock = receiverKeyBytes - rsaOaepDigestOverhead;
    final sigSize = senderKeyBytes;
    final paddingBytes =
        _alignPad(plainBlock, sequenceAndBodyLen + 1 + sigSize);
    final inner = sequenceAndBodyLen + 1 + paddingBytes + sigSize;
    final blocks = inner ~/ plainBlock;
    return blocks * receiverKeyBytes;
  }

  int predictSymmetricInnerBytes({required int sequenceAndBodyLen}) {
    final paddingBytes =
        _alignPad(symBlockSize, sequenceAndBodyLen + 1 + symSignatureSize);
    return sequenceAndBodyLen + 1 + paddingBytes + symSignatureSize;
  }

  // ----- Framing-aware OpcUaSecurityPolicy hooks -------------------

  @override
  int calculateOpnInnerSize(int sequenceAndBodyLen) {
    final priv = ownPrivateKey;
    final pub = peerPublicKey;
    if (priv == null || pub == null) {
      throw StateError(
          '$runtimeType: ownPrivateKey + peerPublicKey required to '
          'predict OPN inner size');
    }
    return predictOpnInnerBytes(
      sequenceAndBodyLen: sequenceAndBodyLen,
      receiverKeyBytes: (pub.modulus!.bitLength + 7) ~/ 8,
      senderKeyBytes: (priv.modulus!.bitLength + 7) ~/ 8,
    );
  }

  @override
  int calculateSymmetricInnerSize(int sequenceAndBodyLen) =>
      predictSymmetricInnerBytes(sequenceAndBodyLen: sequenceAndBodyLen);

  @override
  Uint8List signEncryptOpn({
    required List<int> headerContext,
    required List<int> sequenceAndBody,
  }) {
    final priv = ownPrivateKey;
    final pub = peerPublicKey;
    if (priv == null || pub == null) {
      throw StateError(
          '$runtimeType: ownPrivateKey + peerPublicKey required');
    }
    return _signEncryptOpnInner(
      headerContext: headerContext,
      sequenceAndBody: sequenceAndBody,
      peerPublicKey: pub,
      ourPrivateKey: priv,
    );
  }

  @override
  Uint8List verifyDecryptOpn({
    required List<int> headerContext,
    required List<int> ciphertext,
  }) {
    final priv = ownPrivateKey;
    final pub = peerPublicKey;
    if (priv == null || pub == null) {
      throw StateError(
          '$runtimeType: ownPrivateKey + peerPublicKey required');
    }
    return _verifyDecryptOpnInner(
      headerContext: headerContext,
      ciphertext: ciphertext,
      ourPrivateKey: priv,
      peerPublicKey: pub,
    );
  }

  @override
  Uint8List signEncryptSymmetric({
    required List<int> headerContext,
    required List<int> sequenceAndBody,
  }) {
    final keys = channelKeys;
    if (keys == null) {
      throw StateError('$runtimeType: channelKeys not bound');
    }
    final sigKey = isClient ? keys.clientSigning : keys.serverSigning;
    final encKey = isClient ? keys.clientEncrypting : keys.serverEncrypting;
    final iv = isClient ? keys.clientIv : keys.serverIv;
    return _signEncryptSymmetricInner(
      headerContext: headerContext,
      sequenceAndBody: sequenceAndBody,
      signingKey: sigKey,
      encryptingKey: encKey,
      iv: iv,
    );
  }

  @override
  Uint8List verifyDecryptSymmetric({
    required List<int> headerContext,
    required List<int> ciphertext,
  }) {
    final keys = channelKeys;
    if (keys == null) {
      throw StateError('$runtimeType: channelKeys not bound');
    }
    final sigKey = isClient ? keys.serverSigning : keys.clientSigning;
    final encKey = isClient ? keys.serverEncrypting : keys.clientEncrypting;
    final iv = isClient ? keys.serverIv : keys.clientIv;
    return _verifyDecryptSymmetricInner(
      headerContext: headerContext,
      ciphertext: ciphertext,
      signingKey: sigKey,
      encryptingKey: encKey,
      iv: iv,
    );
  }

  // ----- Asymmetric inner ------------------------------------------

  Uint8List _signEncryptOpnInner({
    required List<int> headerContext,
    required List<int> sequenceAndBody,
    required OpcUaRsaPublicKey peerPublicKey,
    required OpcUaRsaPrivateKey ourPrivateKey,
  }) {
    final receiverKeyBytes =
        (peerPublicKey.modulus!.bitLength + 7) ~/ 8;
    final senderKeyBytes =
        (ourPrivateKey.modulus!.bitLength + 7) ~/ 8;
    final plainBlock = receiverKeyBytes - rsaOaepDigestOverhead;
    final sigSize = senderKeyBytes;

    final paddingBytes =
        _alignPad(plainBlock, sequenceAndBody.length + 1 + sigSize);

    final preSign = BytesBuilder(copy: false)
      ..add(sequenceAndBody)
      ..addByte(paddingBytes);
    for (var i = 0; i < paddingBytes; i++) {
      preSign.addByte(paddingBytes);
    }

    final toSign = BytesBuilder(copy: false)
      ..add(headerContext)
      ..add(preSign.toBytes());
    final signature = _signAsymmetric(ourPrivateKey, toSign.toBytes());
    if (signature.length != sigSize) {
      throw StateError(
          'unexpected RSA signature size ${signature.length} (want $sigSize)');
    }

    final plain = BytesBuilder(copy: false)
      ..add(preSign.toBytes())
      ..add(signature);
    final plainBytes = plain.toBytes();
    if (plainBytes.length % plainBlock != 0) {
      throw StateError(
          'OPN plaintext misaligned: ${plainBytes.length} % $plainBlock');
    }

    final cipher = BytesBuilder(copy: false);
    for (var i = 0; i < plainBytes.length; i += plainBlock) {
      final block = plainBytes.sublist(i, i + plainBlock);
      cipher.add(rsaOaepEncrypt(
        publicKey: peerPublicKey,
        plaintext: block,
        useSha256: true,
      ));
    }
    return cipher.toBytes();
  }

  Uint8List _verifyDecryptOpnInner({
    required List<int> headerContext,
    required List<int> ciphertext,
    required OpcUaRsaPrivateKey ourPrivateKey,
    required OpcUaRsaPublicKey peerPublicKey,
  }) {
    final receiverKeyBytes =
        (ourPrivateKey.modulus!.bitLength + 7) ~/ 8;
    if (ciphertext.length % receiverKeyBytes != 0) {
      throw StateError(
          'OPN ciphertext misaligned: ${ciphertext.length} % $receiverKeyBytes');
    }
    final plain = BytesBuilder(copy: false);
    for (var i = 0; i < ciphertext.length; i += receiverKeyBytes) {
      final block = ciphertext.sublist(i, i + receiverKeyBytes);
      plain.add(rsaOaepDecrypt(
        privateKey: ourPrivateKey,
        ciphertext: block,
        useSha256: true,
      ));
    }
    final plainBytes = plain.toBytes();

    final senderKeyBytes =
        (peerPublicKey.modulus!.bitLength + 7) ~/ 8;
    if (plainBytes.length < senderKeyBytes + 1) {
      throw StateError('decrypted OPN plaintext too short');
    }
    final signedRange =
        plainBytes.sublist(0, plainBytes.length - senderKeyBytes);
    final signature = plainBytes.sublist(plainBytes.length - senderKeyBytes);

    final toVerify = BytesBuilder(copy: false)
      ..add(headerContext)
      ..add(signedRange);
    if (!_verifyAsymmetric(peerPublicKey, toVerify.toBytes(), signature)) {
      throw StateError('OPN signature verification failed');
    }

    if (signedRange.isEmpty) {
      throw StateError('OPN signed range empty');
    }
    final paddingBytes = signedRange.last;
    if (paddingBytes + 1 > signedRange.length) {
      throw StateError('OPN padding length out of range');
    }
    return Uint8List.fromList(
        signedRange.sublist(0, signedRange.length - 1 - paddingBytes));
  }

  // ----- Symmetric inner -------------------------------------------

  Uint8List _signEncryptSymmetricInner({
    required List<int> headerContext,
    required List<int> sequenceAndBody,
    required List<int> signingKey,
    required List<int> encryptingKey,
    required List<int> iv,
  }) {
    final paddingBytes = _alignPad(
        symBlockSize, sequenceAndBody.length + 1 + symSignatureSize);

    final preSign = BytesBuilder(copy: false)
      ..add(sequenceAndBody)
      ..addByte(paddingBytes);
    for (var i = 0; i < paddingBytes; i++) {
      preSign.addByte(paddingBytes);
    }

    final toSign = BytesBuilder(copy: false)
      ..add(headerContext)
      ..add(preSign.toBytes());
    final signature = hmacSha256(signingKey, toSign.toBytes());

    final plain = BytesBuilder(copy: false)
      ..add(preSign.toBytes())
      ..add(signature);
    final plainBytes = plain.toBytes();
    if (plainBytes.length % symBlockSize != 0) {
      throw StateError(
          'symmetric plaintext misaligned: ${plainBytes.length} % $symBlockSize');
    }
    return aesCbcEncrypt(
      key: encryptingKey,
      iv: iv,
      plaintext: plainBytes,
      pkcs7Pad: false,
    );
  }

  Uint8List _verifyDecryptSymmetricInner({
    required List<int> headerContext,
    required List<int> ciphertext,
    required List<int> signingKey,
    required List<int> encryptingKey,
    required List<int> iv,
  }) {
    if (ciphertext.length % symBlockSize != 0) {
      throw StateError(
          'symmetric ciphertext misaligned: ${ciphertext.length} % $symBlockSize');
    }
    final plain = aesCbcDecrypt(
      key: encryptingKey,
      iv: iv,
      ciphertext: ciphertext,
      pkcs7Pad: false,
    );
    if (plain.length < symSignatureSize + 1) {
      throw StateError('decrypted symmetric plaintext too short');
    }
    final signedRange = plain.sublist(0, plain.length - symSignatureSize);
    final signature = plain.sublist(plain.length - symSignatureSize);

    final toVerify = BytesBuilder(copy: false)
      ..add(headerContext)
      ..add(signedRange);
    final expected = hmacSha256(signingKey, toVerify.toBytes());
    if (!_constantTimeEq(signature, expected)) {
      throw StateError('symmetric HMAC verification failed');
    }

    final paddingBytes = signedRange.last;
    if (paddingBytes + 1 > signedRange.length) {
      throw StateError('symmetric padding length out of range');
    }
    return Uint8List.fromList(
        signedRange.sublist(0, signedRange.length - 1 - paddingBytes));
  }
}

/// `Aes128_Sha256_RsaOaep` (Part 7 §6.1.4).
class Aes128Sha256RsaOaepSecurityPolicy extends _AesSha256PolicyBase {
  Aes128Sha256RsaOaepSecurityPolicy({
    super.ownPrivateKey,
    super.peerPublicKey,
    super.isClient,
    super.channelKeys,
  }) : super(
          policyUri: kSecurityPolicyAes128Sha256RsaOaepUri,
          symEncryptingKeySize: 16, // AES-128
          rsaOaepDigestOverhead: 66, // SHA-256 = 32 → 2*32+2
        );

  @override
  Uint8List _signAsymmetric(
          OpcUaRsaPrivateKey privateKey, List<int> message) =>
      rsaPkcs1Sha256Sign(privateKey: privateKey, message: message);

  @override
  bool _verifyAsymmetric(OpcUaRsaPublicKey publicKey, List<int> message,
          List<int> signature) =>
      rsaPkcs1Sha256Verify(
          publicKey: publicKey, message: message, signature: signature);
}

/// `Aes256_Sha256_RsaPss` (Part 7 §6.1.5). RSA-PSS-SHA256 for the
/// asymmetric signature; AES-256-CBC for symmetric encryption.
class Aes256Sha256RsaPssSecurityPolicy extends _AesSha256PolicyBase {
  Aes256Sha256RsaPssSecurityPolicy({
    super.ownPrivateKey,
    super.peerPublicKey,
    super.isClient,
    super.channelKeys,
  }) : super(
          policyUri: kSecurityPolicyAes256Sha256RsaPssUri,
          symEncryptingKeySize: 32, // AES-256
          rsaOaepDigestOverhead: 66, // SHA-256
        );

  @override
  Uint8List _signAsymmetric(
          OpcUaRsaPrivateKey privateKey, List<int> message) =>
      rsaPssSha256Sign(privateKey: privateKey, message: message);

  @override
  bool _verifyAsymmetric(OpcUaRsaPublicKey publicKey, List<int> message,
          List<int> signature) =>
      rsaPssSha256Verify(
          publicKey: publicKey, message: message, signature: signature);
}

int _alignPad(int blockSize, int bytesBeforePad) {
  final r = bytesBeforePad % blockSize;
  return r == 0 ? 0 : blockSize - r;
}

bool _constantTimeEq(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
