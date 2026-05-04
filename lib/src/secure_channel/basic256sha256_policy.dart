/// `Basic256Sha256` security policy implementation per OPC UA Part 7
/// §6.1 + Part 6 §6.7.
///
/// Algorithm bundle:
///   - Asymmetric encryption  : RSA-OAEP-SHA1
///   - Asymmetric signature   : RSA-PKCS1-v1.5-SHA256
///   - Symmetric encryption   : AES-256-CBC
///   - Symmetric signature    : HMAC-SHA-256
///   - Key derivation         : P_SHA256
///
/// This policy operates *with header context* — it cannot use the
/// body-only [OpcUaSecurityPolicy] hooks, because the OPN signature
/// must cover the message header + asymmetric security header bytes
/// that aren't passed to the body-only hooks.
///
/// Callers (typically the SecureChannel framing layer) drive this via
/// [signEncryptOpnInner] / [verifyDecryptOpnInner] for OPN frames and
/// [signEncryptSymmetricInner] / [verifyDecryptSymmetricInner] for
/// MSG / CLO frames. The body-only hooks throw — they remain for
/// the [OpcUaSecurityPolicy] interface contract.
library;

import 'dart:typed_data';

import '../crypto/primitives.dart';
import '../crypto/rsa.dart';
import 'security_policy.dart';

/// Bundled symmetric channel keys derived from the client + server
/// nonces at OPN time. Used for every MSG / CLO frame on the channel.
class Basic256Sha256ChannelKeys {
  /// Key for HMAC-SHA-256 signing of *outbound client → server* frames.
  final Uint8List clientSigning;

  /// Key for AES-256-CBC of *outbound client → server* frames.
  final Uint8List clientEncrypting;

  /// IV for AES-256-CBC of *outbound client → server* frames.
  final Uint8List clientIv;

  /// Key for HMAC-SHA-256 signing of *inbound server → client* frames.
  final Uint8List serverSigning;

  /// Key for AES-256-CBC of *inbound server → client* frames.
  final Uint8List serverEncrypting;

  /// IV for AES-256-CBC of *inbound server → client* frames.
  final Uint8List serverIv;

  const Basic256Sha256ChannelKeys({
    required this.clientSigning,
    required this.clientEncrypting,
    required this.clientIv,
    required this.serverSigning,
    required this.serverEncrypting,
    required this.serverIv,
  });
}

class Basic256Sha256SecurityPolicy extends CryptoSecurityPolicy {
  /// HMAC-SHA-256 output size in bytes.
  static const int symSignatureSize = 32;

  /// AES-256 key size in bytes.
  static const int symEncryptingKeySize = 32;

  /// AES-CBC IV / block size in bytes.
  static const int symBlockSize = 16;

  /// RSA-OAEP-SHA1 overhead in bytes (`2 * SHA1.digestSize + 2`).
  static const int rsaOaepSha1Overhead = 42;

  /// Our X.509 RSA private key — used to sign outgoing OPN frames.
  /// Optional: only required when calling the framing-aware
  /// [signEncryptOpn] / [verifyDecryptOpn] methods on this policy
  /// instance. Lower-level [signEncryptOpnInner] takes the keys
  /// per-call and works with a no-key policy instance (used by
  /// tests + auditable in-isolation crypto).
  final OpcUaRsaPrivateKey? ownPrivateKey;

  /// Peer's X.509 RSA public key — used to encrypt outgoing OPN
  /// frames and verify incoming signatures.
  final OpcUaRsaPublicKey? peerPublicKey;

  /// `true` when this policy instance represents the *client* side of
  /// the channel (sends with `client*` keys, receives `server*`).
  /// `false` for the server side.
  final bool isClient;

  /// Channel keys derived after the OPN handshake. Set via
  /// [bindChannelKeys] before any MSG / CLO frame.
  Basic256Sha256ChannelKeys? channelKeys;

  Basic256Sha256SecurityPolicy({
    this.ownPrivateKey,
    this.peerPublicKey,
    this.isClient = true,
    this.channelKeys,
  }) : super(policyUri: kSecurityPolicyBasic256Sha256Uri);

  /// Set the symmetric channel keys after the OPN handshake. Returns
  /// `this` for fluent chaining.
  Basic256Sha256SecurityPolicy bindChannelKeys(
      Basic256Sha256ChannelKeys keys) {
    channelKeys = keys;
    return this;
  }

  // ----- Body-only OpcUaSecurityPolicy hooks (unsupported) ---------

  @override
  Uint8List signOutboundOpn(List<int> body) => throw UnsupportedError(
      'Basic256Sha256: use signEncryptOpnInner with header context');

  @override
  Uint8List unsealInboundOpn(List<int> body) => throw UnsupportedError(
      'Basic256Sha256: use verifyDecryptOpnInner with header context');

  @override
  Uint8List signOutboundSymmetric(List<int> body) => throw UnsupportedError(
      'Basic256Sha256: use signEncryptSymmetricInner with header context');

  @override
  Uint8List unsealInboundSymmetric(List<int> body) => throw UnsupportedError(
      'Basic256Sha256: use verifyDecryptSymmetricInner with header context');

  // ----- Framing-aware OpcUaSecurityPolicy hooks -------------------

  @override
  int calculateOpnInnerSize(int sequenceAndBodyLen) {
    final peer = peerPublicKey;
    final own = ownPrivateKey;
    if (peer == null || own == null) {
      throw StateError(
          'Basic256Sha256: ownPrivateKey + peerPublicKey required to '
          'predict OPN inner size');
    }
    final receiverKeyBytes = (peer.modulus!.bitLength + 7) ~/ 8;
    final senderKeyBytes = (own.modulus!.bitLength + 7) ~/ 8;
    return predictOpnInnerSize(
      sequenceAndBodyLen: sequenceAndBodyLen,
      receiverKeyBytes: receiverKeyBytes,
      senderKeyBytes: senderKeyBytes,
    );
  }

  @override
  int calculateSymmetricInnerSize(int sequenceAndBodyLen) =>
      predictSymmetricInnerSize(sequenceAndBodyLen: sequenceAndBodyLen);

  @override
  Uint8List signEncryptOpn({
    required List<int> headerContext,
    required List<int> sequenceAndBody,
  }) {
    final priv = ownPrivateKey;
    final pub = peerPublicKey;
    if (priv == null || pub == null) {
      throw StateError(
          'Basic256Sha256: ownPrivateKey + peerPublicKey required to '
          'sign+encrypt OPN');
    }
    return signEncryptOpnInner(
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
          'Basic256Sha256: ownPrivateKey + peerPublicKey required to '
          'verify+decrypt OPN');
    }
    return verifyDecryptOpnInner(
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
      throw StateError(
          'Basic256Sha256: channelKeys not bound — call bindChannelKeys');
    }
    final sigKey = isClient ? keys.clientSigning : keys.serverSigning;
    final encKey = isClient ? keys.clientEncrypting : keys.serverEncrypting;
    final iv = isClient ? keys.clientIv : keys.serverIv;
    return signEncryptSymmetricInner(
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
      throw StateError(
          'Basic256Sha256: channelKeys not bound — call bindChannelKeys');
    }
    // Receiving side uses the *peer's* outbound keys: client receives
    // server-sent frames signed/encrypted with server* keys.
    final sigKey = isClient ? keys.serverSigning : keys.clientSigning;
    final encKey = isClient ? keys.serverEncrypting : keys.clientEncrypting;
    final iv = isClient ? keys.serverIv : keys.clientIv;
    return verifyDecryptSymmetricInner(
      headerContext: headerContext,
      ciphertext: ciphertext,
      signingKey: sigKey,
      encryptingKey: encKey,
      iv: iv,
    );
  }

  // ----- Key derivation --------------------------------------------

  /// Derive the channel keys from the OPN nonces. Per Part 6 §6.7.5,
  /// `clientKeys = P_SHA256(serverNonce, clientNonce, 80)` and
  /// `serverKeys = P_SHA256(clientNonce, serverNonce, 80)`. The 80
  /// bytes break down as `signing(32) || encrypting(32) || iv(16)`.
  static Basic256Sha256ChannelKeys deriveChannelKeys({
    required List<int> clientNonce,
    required List<int> serverNonce,
  }) {
    const total = symSignatureSize + symEncryptingKeySize + symBlockSize;
    final c = pSha256(secret: serverNonce, seed: clientNonce, length: total);
    final s = pSha256(secret: clientNonce, seed: serverNonce, length: total);
    Uint8List slice(Uint8List src, int from, int to) =>
        Uint8List.fromList(src.sublist(from, to));
    return Basic256Sha256ChannelKeys(
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

  // ----- Frame size pre-computation --------------------------------

  /// Predict the encrypted size of the inner OPN payload (everything
  /// after the asymmetric security header) given the plaintext
  /// `seqHeader + body` length and the *receiver* RSA key size in
  /// bytes. The framing layer needs this before signing because the
  /// computed size goes into the message header — which itself is in
  /// the signed range.
  ///
  /// Distinct name from the instance-method [calculateOpnInnerSize]
  /// override (single-arg, reads keys from policy fields) because Dart
  /// disallows static + instance members with the same name.
  static int predictOpnInnerSize({
    required int sequenceAndBodyLen,
    required int receiverKeyBytes,
    required int senderKeyBytes,
  }) {
    final plainBlock = receiverKeyBytes - rsaOaepSha1Overhead;
    final sigSize = senderKeyBytes;
    final paddingBytes =
        _alignmentPad(plainBlock, sequenceAndBodyLen + 1 + sigSize);
    final innerPlainLen =
        sequenceAndBodyLen + 1 + paddingBytes + sigSize;
    final blocks = innerPlainLen ~/ plainBlock;
    return blocks * receiverKeyBytes;
  }

  /// Predict the size of the encrypted symmetric (MSG / CLO) inner
  /// payload given the plaintext `seqHeader + body` length.
  static int predictSymmetricInnerSize({
    required int sequenceAndBodyLen,
  }) {
    final paddingBytes = _alignmentPad(
        symBlockSize, sequenceAndBodyLen + 1 + symSignatureSize);
    return sequenceAndBodyLen + 1 + paddingBytes + symSignatureSize;
  }

  // ----- Asymmetric (OPN) sign + encrypt ---------------------------

  /// Sign and encrypt the inner OPN payload. Returns the bytes that
  /// the framing layer writes to the wire after the asymmetric
  /// security header.
  ///
  /// [headerContext] is the bytes that must be signed but are not
  /// encrypted — typically `messageHeader (12) || asymHeader`. The
  /// caller composes those before calling and the message header's
  /// size field must already reflect the post-encryption total
  /// (compute via [calculateOpnInnerSize]).
  ///
  /// [sequenceAndBody] is the 8-byte SequenceHeader followed by the
  /// service body bytes.
  Uint8List signEncryptOpnInner({
    required List<int> headerContext,
    required List<int> sequenceAndBody,
    required OpcUaRsaPublicKey peerPublicKey,
    required OpcUaRsaPrivateKey ourPrivateKey,
  }) {
    final receiverKeyBytes =
        (peerPublicKey.modulus!.bitLength + 7) ~/ 8;
    final senderKeyBytes =
        (ourPrivateKey.modulus!.bitLength + 7) ~/ 8;
    final plainBlock = receiverKeyBytes - rsaOaepSha1Overhead;
    final sigSize = senderKeyBytes;

    final paddingBytes =
        _alignmentPad(plainBlock, sequenceAndBody.length + 1 + sigSize);

    // Plaintext layout (before encryption): seqAndBody || padByte ||
    //   padByte * paddingBytes || signature.
    final preSign = BytesBuilder(copy: false)
      ..add(sequenceAndBody)
      ..addByte(paddingBytes);
    for (var i = 0; i < paddingBytes; i++) {
      preSign.addByte(paddingBytes);
    }

    // Signature spans (headerContext || preSign).
    final toSign = BytesBuilder(copy: false)
      ..add(headerContext)
      ..add(preSign.toBytes());
    final signature =
        rsaPkcs1Sha256Sign(privateKey: ourPrivateKey, message: toSign.toBytes());
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

    // Encrypt block-by-block with RSA-OAEP-SHA1 using receiver public key.
    final cipher = BytesBuilder(copy: false);
    for (var i = 0; i < plainBytes.length; i += plainBlock) {
      final block = plainBytes.sublist(i, i + plainBlock);
      cipher.add(
        rsaOaepEncrypt(publicKey: peerPublicKey, plaintext: block),
      );
    }
    return cipher.toBytes();
  }

  /// Inverse of [signEncryptOpnInner]. Decrypts with our private key
  /// (RSA-OAEP-SHA1), verifies the signature with the peer public key
  /// (RSA-PKCS1-v1.5-SHA256), and strips the padding. Returns the
  /// recovered `seqHeader + body` bytes.
  Uint8List verifyDecryptOpnInner({
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
      plain.add(
        rsaOaepDecrypt(privateKey: ourPrivateKey, ciphertext: block),
      );
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
    final ok = rsaPkcs1Sha256Verify(
      publicKey: peerPublicKey,
      message: toVerify.toBytes(),
      signature: signature,
    );
    if (!ok) {
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

  // ----- Symmetric (MSG / CLO) sign + encrypt ----------------------

  /// Sign and AES-encrypt a symmetric inner payload. Returns the
  /// bytes that the framing layer writes after the symmetric security
  /// header.
  ///
  /// [headerContext] is `messageHeader (12) || symHeader (4)` — the
  /// bytes covered by the HMAC but not encrypted. The size field in
  /// the message header must already reflect the post-encryption
  /// total (compute via [calculateSymmetricInnerSize]).
  Uint8List signEncryptSymmetricInner({
    required List<int> headerContext,
    required List<int> sequenceAndBody,
    required List<int> signingKey,
    required List<int> encryptingKey,
    required List<int> iv,
  }) {
    final paddingBytes = _alignmentPad(
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

  /// Inverse of [signEncryptSymmetricInner].
  Uint8List verifyDecryptSymmetricInner({
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

/// Returns `(blockSize - bytesBeforePad mod blockSize) mod blockSize`
/// — the number of zero-extension bytes that line up the next byte
/// to a block boundary.
int _alignmentPad(int blockSize, int bytesBeforePad) {
  final r = bytesBeforePad % blockSize;
  return r == 0 ? 0 : blockSize - r;
}

/// Constant-time equality for HMAC tags. Diff accumulates bit-OR of
/// XOR per byte; only zero on full match.
bool _constantTimeEq(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
