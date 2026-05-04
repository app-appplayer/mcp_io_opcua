/// Pluggable signature / encryption hooks for OPC UA SecureChannel
/// frames.
///
/// OPC UA Part 6 §6.1 defines a fixed set of security policies. Each
/// policy specifies:
///   - which asymmetric algorithm protects the OPN handshake
///     (`Basic128Rsa15` / `Basic256` / `Basic256Sha256` / `Aes128…`),
///   - which symmetric algorithm protects MSG / CLO frames after the
///     handshake completes,
///   - how nonces / signatures / paddings are layered onto the
///     `body` bytes that the rest of the codec stack sees.
///
/// The SecureChannel framing in this package handles *plaintext*
/// (policy `None`) directly. For the signed / encrypted policies the
/// framing path delegates body wrapping to an [OpcUaSecurityPolicy]
/// implementation — typically backed by `package:pointycastle` or a
/// host-supplied crypto provider. This file ships the abstract +
/// [NoneSecurityPolicy] (a no-op that is the only policy used inside
/// the package's own tests).
library;

import 'dart:typed_data';

/// `securityPolicyUri` value for unsigned, unencrypted channels —
/// re-exported for convenience from the secure-channel framing
/// module.
const String kSecurityPolicyNoneUri =
    'http://opcfoundation.org/UA/SecurityPolicy#None';

const String kSecurityPolicyBasic128Rsa15Uri =
    'http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15';

const String kSecurityPolicyBasic256Uri =
    'http://opcfoundation.org/UA/SecurityPolicy#Basic256';

const String kSecurityPolicyBasic256Sha256Uri =
    'http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256';

const String kSecurityPolicyAes128Sha256RsaOaepUri =
    'http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep';

const String kSecurityPolicyAes256Sha256RsaPssUri =
    'http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss';

/// Hooks called by the SecureChannel framing path on every OPN /
/// MSG / CLO frame.
///
/// Two surfaces:
///
///   * **Body-only hooks** — [signOutboundOpn] / [unsealInboundOpn] /
///     [signOutboundSymmetric] / [unsealInboundSymmetric]. These
///     receive the SequenceHeader+body bytes and return the bytes
///     that go on the wire (encrypted / signed). Used by `None`
///     (identity transform).
///
///   * **Header-context hooks** — [signEncryptOpn] /
///     [verifyDecryptOpn] / [signEncryptSymmetric] /
///     [verifyDecryptSymmetric]. These additionally receive the
///     bytes of the *unencrypted* prefix (message header + asym /
///     sym security header) so that the signature can cover the
///     full per-OPC UA Part 6 §6.7 spec range. The default
///     implementation delegates to the body-only hook (ignoring
///     header context), which is correct for `None`.
///
/// The framing layer always calls the header-context hooks. Crypto
/// policies (Basic256Sha256, Aes*) override them; `None` lets the
/// default body-only delegation pass through.
///
/// Frame-size pre-computation:
///
///   * [calculateOpnInnerSize] / [calculateSymmetricInnerSize] —
///     return the post-encryption byte count for the inner payload
///     given the plain `seq+body` length. Used so the framing layer
///     can fill the message-header `size` field *before* signing
///     (the size is in the signed range). Default = identity (no
///     overhead — correct for `None`).
abstract class OpcUaSecurityPolicy {
  const OpcUaSecurityPolicy();

  /// `securityPolicyUri` carried in the AsymmetricSecurityHeader of
  /// every OPN frame (and recovered on the receive side).
  String get policyUri;

  /// True when the policy is `None` — the framing layer skips the
  /// crypto detour entirely on this path.
  bool get isNone => policyUri == kSecurityPolicyNoneUri;

  /// Asymmetric (OPN-time) outbound transform.
  Uint8List signOutboundOpn(List<int> body);

  /// Asymmetric inbound transform — verifies + unseals.
  Uint8List unsealInboundOpn(List<int> body);

  /// Symmetric (MSG / CLO) outbound transform.
  Uint8List signOutboundSymmetric(List<int> body);

  /// Symmetric inbound transform — verifies + unseals.
  Uint8List unsealInboundSymmetric(List<int> body);

  /// Predicted post-encryption inner-payload size for an OPN frame.
  /// Default: identity (matches `None`).
  int calculateOpnInnerSize(int sequenceAndBodyLen) => sequenceAndBodyLen;

  /// Predicted post-encryption inner-payload size for a symmetric
  /// (MSG / CLO) frame. Default: identity (matches `None`).
  int calculateSymmetricInnerSize(int sequenceAndBodyLen) =>
      sequenceAndBodyLen;

  /// Sign + encrypt the OPN inner payload, with [headerContext] = the
  /// already-built message header + asym security header bytes (which
  /// must be in the signed range per Part 6 §6.7.4). Default:
  /// delegates to [signOutboundOpn] (None: identity).
  Uint8List signEncryptOpn({
    required List<int> headerContext,
    required List<int> sequenceAndBody,
  }) =>
      signOutboundOpn(sequenceAndBody);

  /// Verify + decrypt an OPN inner payload. Default delegates to
  /// [unsealInboundOpn].
  Uint8List verifyDecryptOpn({
    required List<int> headerContext,
    required List<int> ciphertext,
  }) =>
      unsealInboundOpn(ciphertext);

  /// Sign + encrypt a symmetric (MSG / CLO) inner payload, with
  /// [headerContext] = message header + sym security header bytes.
  /// Default delegates to [signOutboundSymmetric].
  Uint8List signEncryptSymmetric({
    required List<int> headerContext,
    required List<int> sequenceAndBody,
  }) =>
      signOutboundSymmetric(sequenceAndBody);

  /// Verify + decrypt a symmetric inner payload. Default delegates to
  /// [unsealInboundSymmetric].
  Uint8List verifyDecryptSymmetric({
    required List<int> headerContext,
    required List<int> ciphertext,
  }) =>
      unsealInboundSymmetric(ciphertext);
}

/// `securityPolicy = None` — pass-through for every direction. Used
/// by tests, simulators, and any deployment that already protects the
/// channel at a lower layer (TLS, VPN, isolated industrial subnet).
class NoneSecurityPolicy extends OpcUaSecurityPolicy {
  const NoneSecurityPolicy();

  @override
  String get policyUri => kSecurityPolicyNoneUri;

  @override
  bool get isNone => true;

  @override
  Uint8List signOutboundOpn(List<int> body) => Uint8List.fromList(body);

  @override
  Uint8List unsealInboundOpn(List<int> body) => Uint8List.fromList(body);

  @override
  Uint8List signOutboundSymmetric(List<int> body) => Uint8List.fromList(body);

  @override
  Uint8List unsealInboundSymmetric(List<int> body) =>
      Uint8List.fromList(body);
}

/// Abstract base for sign / encrypt policies that delegate the crypto
/// to a caller-supplied implementation. Subclasses override the four
/// hooks with their actual transforms; this base just enforces
/// `isNone == false` and the URI.
abstract class CryptoSecurityPolicy extends OpcUaSecurityPolicy {
  CryptoSecurityPolicy({required this.policyUri});

  @override
  final String policyUri;

  @override
  bool get isNone => false;
}
