/// OPC UA SecureChannel message framing (Part 6 §7.1.2).
///
/// Message header (12 bytes for OPN/CLO/MSG):
///   offset 0..2  : message type ("OPN" | "CLO" | "MSG")
///   offset 3     : chunk type ('F' = final, 'C' = intermediate, 'A' = abort)
///   offset 4..7  : message size (uint32, including the 12-byte header)
///   offset 8..11 : SecureChannelId (uint32)
///
/// OPN frames append an AsymmetricSecurityHeader:
///   securityPolicyUri               OPC UA String
///   senderCertificate               OPC UA ByteString (null in 'None' mode)
///   receiverCertificateThumbprint   OPC UA ByteString (null in 'None' mode)
///
/// MSG/CLO frames append a SymmetricSecurityHeader:
///   tokenId                         uint32
///
/// Both append a SequenceHeader:
///   sequenceNumber  uint32
///   requestId       uint32
///
/// Followed by the body (TypeId + service request/response).
///
/// This module implements the *plaintext* path used for `securityPolicyUri ==
/// "http://opcfoundation.org/UA/SecurityPolicy#None"`. Signed / encrypted
/// policies (Basic128Rsa15, Basic256, Basic256Sha256, Aes128/256_Sha256_RsaOaep)
/// are layered on top by wrapping the body bytes — the framing remains
/// identical.
library;

import 'dart:typed_data';

import '../encoding/binary_reader.dart';
import '../encoding/binary_writer.dart';
import '../opcua_types.dart';
import 'security_policy.dart';

/// `securityPolicyUri` value for unsigned, unencrypted channels.
const String kOpcUaSecurityPolicyNoneUri =
    'http://opcfoundation.org/UA/SecurityPolicy#None';

enum OpcUaSecureMessageType { opn, clo, msg }

extension on OpcUaSecureMessageType {
  String get wire => switch (this) {
        OpcUaSecureMessageType.opn => 'OPN',
        OpcUaSecureMessageType.clo => 'CLO',
        OpcUaSecureMessageType.msg => 'MSG',
      };
}

enum OpcUaChunkType { intermediate, finalChunk, abort }

extension on OpcUaChunkType {
  int get wire => switch (this) {
        OpcUaChunkType.intermediate => 'C'.codeUnitAt(0),
        OpcUaChunkType.finalChunk => 'F'.codeUnitAt(0),
        OpcUaChunkType.abort => 'A'.codeUnitAt(0),
      };
}

/// SequenceHeader (Part 6 §6.7.2.1).
class OpcUaSequenceHeader {
  final int sequenceNumber;
  final int requestId;

  const OpcUaSequenceHeader({
    required this.sequenceNumber,
    required this.requestId,
  });

  void encode(BinaryWriter w) {
    w.writeUint32(sequenceNumber);
    w.writeUint32(requestId);
  }

  factory OpcUaSequenceHeader.decode(BinaryReader r) {
    return OpcUaSequenceHeader(
      sequenceNumber: r.readUint32(),
      requestId: r.readUint32(),
    );
  }
}

/// AsymmetricSecurityHeader (OPN frames only).
class OpcUaAsymmetricSecurityHeader {
  /// Always non-null. Use [kOpcUaSecurityPolicyNoneUri] for plaintext.
  final String securityPolicyUri;

  /// Sender X.509 certificate. `null` for the None policy.
  final List<int>? senderCertificate;

  /// SHA-1 thumbprint of the receiver certificate. `null` for None.
  final List<int>? receiverCertificateThumbprint;

  const OpcUaAsymmetricSecurityHeader({
    this.securityPolicyUri = kOpcUaSecurityPolicyNoneUri,
    this.senderCertificate,
    this.receiverCertificateThumbprint,
  });

  bool get isNonePolicy => securityPolicyUri == kOpcUaSecurityPolicyNoneUri;

  void encode(BinaryWriter w) {
    w.writeStringOrNull(securityPolicyUri);
    w.writeByteStringOrNull(senderCertificate);
    w.writeByteStringOrNull(receiverCertificateThumbprint);
  }

  factory OpcUaAsymmetricSecurityHeader.decode(BinaryReader r) {
    return OpcUaAsymmetricSecurityHeader(
      securityPolicyUri: r.readStringOrNull() ?? '',
      senderCertificate: r.readByteStringOrNull(),
      receiverCertificateThumbprint: r.readByteStringOrNull(),
    );
  }
}

/// SymmetricSecurityHeader (MSG / CLO frames).
class OpcUaSymmetricSecurityHeader {
  final int tokenId;

  const OpcUaSymmetricSecurityHeader({required this.tokenId});

  void encode(BinaryWriter w) => w.writeUint32(tokenId);

  factory OpcUaSymmetricSecurityHeader.decode(BinaryReader r) =>
      OpcUaSymmetricSecurityHeader(tokenId: r.readUint32());
}

/// Top-level decoded SecureChannel frame.
class OpcUaSecureChannelFrame {
  final OpcUaSecureMessageType type;
  final OpcUaChunkType chunk;
  final int secureChannelId;

  /// Populated for OPN frames.
  final OpcUaAsymmetricSecurityHeader? asymmetric;

  /// Populated for MSG / CLO frames.
  final OpcUaSymmetricSecurityHeader? symmetric;

  final OpcUaSequenceHeader sequence;
  final Uint8List body;

  const OpcUaSecureChannelFrame({
    required this.type,
    required this.chunk,
    required this.secureChannelId,
    required this.sequence,
    required this.body,
    this.asymmetric,
    this.symmetric,
  });

  /// Encode an OPN frame (security policy None or otherwise the caller
  /// supplies an [asymmetric] header). The asymmetric header must be
  /// non-null. Returns the full message bytes including the 12-byte
  /// transport header.
  ///
  /// When [policy] is a crypto policy (Basic256Sha256, Aes*), the
  /// body bytes (sequence header + service body) are signed and
  /// encrypted with [OpcUaSecurityPolicy.signEncryptOpn], which
  /// receives the unencrypted prefix (message header + asym header)
  /// as its `headerContext` so the signature covers it per Part 6
  /// §6.7.4. For `None` the default delegation produces an identity
  /// transform.
  static Uint8List encodeOpn({
    required int secureChannelId,
    required OpcUaAsymmetricSecurityHeader asymmetric,
    required OpcUaSequenceHeader sequence,
    required List<int> body,
    OpcUaChunkType chunk = OpcUaChunkType.finalChunk,
    OpcUaSecurityPolicy policy = const NoneSecurityPolicy(),
  }) {
    final secured = _buildSequencePlusBody(sequence, body);

    // Encode the asymmetric security header up-front so we know its
    // length — it's part of the signed range (header context).
    final asymBuf = BinaryWriter(64);
    asymmetric.encode(asymBuf);
    final asymBytes = asymBuf.takeBytes();

    // Predict the post-encryption inner-payload size and assemble
    // the message header (whose `size` field must be in the signed
    // range). For `None` this is identity.
    final innerSize = policy.calculateOpnInnerSize(secured.length);
    final totalSize = 12 + asymBytes.length + innerSize;
    final msgHdr = _buildMessageHeader(
      type: OpcUaSecureMessageType.opn,
      chunk: chunk,
      totalSize: totalSize,
      secureChannelId: secureChannelId,
    );

    final headerContext = Uint8List(msgHdr.length + asymBytes.length)
      ..setRange(0, msgHdr.length, msgHdr)
      ..setRange(msgHdr.length, msgHdr.length + asymBytes.length, asymBytes);

    final wrapped = policy.signEncryptOpn(
      headerContext: headerContext,
      sequenceAndBody: secured,
    );
    if (wrapped.length != innerSize) {
      throw OpcUaProtocolError(
        'security policy size prediction mismatch — '
        'predicted $innerSize, produced ${wrapped.length}',
      );
    }

    final out = Uint8List(totalSize)
      ..setRange(0, msgHdr.length, msgHdr)
      ..setRange(msgHdr.length, msgHdr.length + asymBytes.length, asymBytes)
      ..setRange(msgHdr.length + asymBytes.length, totalSize, wrapped);
    return out;
  }

  /// Encode an MSG / CLO frame using a symmetric token id.
  ///
  /// For a crypto policy, the inner payload (sequence header +
  /// service body) is signed + encrypted with
  /// [OpcUaSecurityPolicy.signEncryptSymmetric], which receives
  /// `messageHeader || symHeader` as its `headerContext` so the
  /// HMAC covers them. For `None` the default delegation is identity.
  static Uint8List encodeSymmetric({
    required OpcUaSecureMessageType type,
    required int secureChannelId,
    required OpcUaSymmetricSecurityHeader symmetric,
    required OpcUaSequenceHeader sequence,
    required List<int> body,
    OpcUaChunkType chunk = OpcUaChunkType.finalChunk,
    OpcUaSecurityPolicy policy = const NoneSecurityPolicy(),
  }) {
    if (type == OpcUaSecureMessageType.opn) {
      throw const OpcUaProtocolError(
        'encodeSymmetric must not be called for OPN — use encodeOpn',
      );
    }
    final secured = _buildSequencePlusBody(sequence, body);

    final symBuf = BinaryWriter(16);
    symmetric.encode(symBuf);
    final symBytes = symBuf.takeBytes();

    final innerSize = policy.calculateSymmetricInnerSize(secured.length);
    final totalSize = 12 + symBytes.length + innerSize;
    final msgHdr = _buildMessageHeader(
      type: type,
      chunk: chunk,
      totalSize: totalSize,
      secureChannelId: secureChannelId,
    );

    final headerContext = Uint8List(msgHdr.length + symBytes.length)
      ..setRange(0, msgHdr.length, msgHdr)
      ..setRange(msgHdr.length, msgHdr.length + symBytes.length, symBytes);

    final wrapped = policy.signEncryptSymmetric(
      headerContext: headerContext,
      sequenceAndBody: secured,
    );
    if (wrapped.length != innerSize) {
      throw OpcUaProtocolError(
        'security policy size prediction mismatch — '
        'predicted $innerSize, produced ${wrapped.length}',
      );
    }

    final out = Uint8List(totalSize)
      ..setRange(0, msgHdr.length, msgHdr)
      ..setRange(msgHdr.length, msgHdr.length + symBytes.length, symBytes)
      ..setRange(msgHdr.length + symBytes.length, totalSize, wrapped);
    return out;
  }

  /// Decode any OPN/CLO/MSG frame. When [policy] is supplied (and
  /// non-`None`), the encrypted body is passed through the matching
  /// inbound transform with the unencrypted prefix (message header
  /// + asym / sym security header) supplied as `headerContext` so
  /// the signature can be verified per Part 6 §6.7.4.
  factory OpcUaSecureChannelFrame.decode(
    List<int> frame, {
    OpcUaSecurityPolicy policy = const NoneSecurityPolicy(),
  }) {
    if (frame.length < 12) {
      throw const OpcUaProtocolError('SecureChannel frame too short');
    }
    final type = _$.parse(String.fromCharCodes(frame.sublist(0, 3)));
    final chunk = _$$.parse(frame[3]);
    final frameBytes = Uint8List.fromList(frame);
    final view = ByteData.sublistView(frameBytes);
    final size = view.getUint32(4, Endian.little);
    if (size != frame.length) {
      throw OpcUaProtocolError(
        'frame size mismatch — declared $size, got ${frame.length}',
      );
    }
    final secureChannelId = view.getUint32(8, Endian.little);

    final reader = BinaryReader(Uint8List.fromList(frame.sublist(12)));
    OpcUaAsymmetricSecurityHeader? asym;
    OpcUaSymmetricSecurityHeader? sym;
    if (type == OpcUaSecureMessageType.opn) {
      asym = OpcUaAsymmetricSecurityHeader.decode(reader);
    } else {
      sym = OpcUaSymmetricSecurityHeader.decode(reader);
    }

    // Header context = message header (12 bytes) + security header
    // bytes. We slice the original frame up to the offset where the
    // security header reading stopped — that is `12 + (header bytes
    // already read)`. The reader's `consumed` count tells us how
    // many bytes from the post-msg-header portion it consumed.
    final consumed = reader.offset;
    final headerEnd = 12 + consumed;
    final headerContext =
        Uint8List.sublistView(frameBytes, 0, headerEnd);

    final encrypted = reader.readBytes(reader.remaining);
    final unsealed = type == OpcUaSecureMessageType.opn
        ? policy.verifyDecryptOpn(
            headerContext: headerContext,
            ciphertext: encrypted,
          )
        : policy.verifyDecryptSymmetric(
            headerContext: headerContext,
            ciphertext: encrypted,
          );
    final inner = BinaryReader(unsealed);
    final seq = OpcUaSequenceHeader.decode(inner);
    final body = inner.readBytes(inner.remaining);
    return OpcUaSecureChannelFrame(
      type: type,
      chunk: chunk,
      secureChannelId: secureChannelId,
      asymmetric: asym,
      symmetric: sym,
      sequence: seq,
      body: body,
    );
  }
}

/// Encode a sequence header followed by the caller-supplied body
/// into a single contiguous byte buffer — exposed so the security
/// policy hook receives a cohesive "plain body" to sign / encrypt.
Uint8List _buildSequencePlusBody(
  OpcUaSequenceHeader seq, List<int> body,
) {
  final w = BinaryWriter(8 + body.length);
  seq.encode(w);
  w.writeBytes(body);
  return w.takeBytes();
}

const _$ = _MessageTypeParse();
const _$$ = _ChunkTypeParse();

class _MessageTypeParse {
  const _MessageTypeParse();
  OpcUaSecureMessageType parse(String s) {
    switch (s) {
      case 'OPN':
        return OpcUaSecureMessageType.opn;
      case 'CLO':
        return OpcUaSecureMessageType.clo;
      case 'MSG':
        return OpcUaSecureMessageType.msg;
    }
    throw OpcUaProtocolError('unknown secure message type: $s');
  }
}

class _ChunkTypeParse {
  const _ChunkTypeParse();
  OpcUaChunkType parse(int code) {
    switch (String.fromCharCode(code)) {
      case 'C':
        return OpcUaChunkType.intermediate;
      case 'F':
        return OpcUaChunkType.finalChunk;
      case 'A':
        return OpcUaChunkType.abort;
    }
    throw OpcUaProtocolError('unknown chunk type: ${String.fromCharCode(code)}');
  }
}

/// Build the 12-byte transport message header. [totalSize] must equal
/// the length of the full frame (header + everything after).
Uint8List _buildMessageHeader({
  required OpcUaSecureMessageType type,
  required OpcUaChunkType chunk,
  required int totalSize,
  required int secureChannelId,
}) {
  final out = Uint8List(12);
  final type3 = type.wire;
  out[0] = type3.codeUnitAt(0);
  out[1] = type3.codeUnitAt(1);
  out[2] = type3.codeUnitAt(2);
  out[3] = chunk.wire;
  final view = ByteData.sublistView(out);
  view.setUint32(4, totalSize, Endian.little);
  view.setUint32(8, secureChannelId, Endian.little);
  return out;
}
