/// SecureChannel service request / response codecs (OPC UA Part 4 §5.5).
///
/// These are the structs carried *inside* OPN frames (and CLO frames for
/// CloseSecureChannel). The transport-level framing (`OPN`/`CLO`/`MSG`
/// header + AsymmetricSecurityHeader / SymmetricSecurityHeader / SequenceHeader)
/// lives in `secure_channel/secure_channel.dart`.
library;

import '../encoding/binary_reader.dart';
import '../encoding/binary_writer.dart';
import 'request_header.dart';

/// `MessageSecurityMode` (Part 4 §7.15).
enum OpcUaSecurityMode {
  invalid(0),
  none(1),
  sign(2),
  signAndEncrypt(3);

  const OpcUaSecurityMode(this.id);
  final int id;

  static OpcUaSecurityMode fromId(int id) {
    if (id < 0 || id > 3) {
      throw ArgumentError.value(id, 'id', 'invalid SecurityMode');
    }
    return OpcUaSecurityMode.values[id];
  }
}

/// `SecurityTokenRequestType` (Part 4 §7.32).
enum OpcUaSecurityTokenRequestType {
  issue(0),
  renew(1);

  const OpcUaSecurityTokenRequestType(this.id);
  final int id;

  static OpcUaSecurityTokenRequestType fromId(int id) {
    if (id < 0 || id > 1) {
      throw ArgumentError.value(id, 'id', 'invalid SecurityTokenRequestType');
    }
    return OpcUaSecurityTokenRequestType.values[id];
  }
}

/// `ChannelSecurityToken` (Part 4 §7.4).
class OpcUaChannelSecurityToken {
  final int channelId;
  final int tokenId;
  final DateTime createdAt;
  final int revisedLifetime;

  const OpcUaChannelSecurityToken({
    required this.channelId,
    required this.tokenId,
    required this.createdAt,
    required this.revisedLifetime,
  });

  void encode(BinaryWriter w) {
    w.writeUint32(channelId);
    w.writeUint32(tokenId);
    w.writeInt64(_dateTimeToTicks(createdAt));
    w.writeUint32(revisedLifetime);
  }

  factory OpcUaChannelSecurityToken.decode(BinaryReader r) {
    return OpcUaChannelSecurityToken(
      channelId: r.readUint32(),
      tokenId: r.readUint32(),
      createdAt: _ticksToDateTime(r.readInt64()),
      revisedLifetime: r.readUint32(),
    );
  }
}

class OpcUaOpenSecureChannelRequest {
  final OpcUaRequestHeader header;
  final int clientProtocolVersion;
  final OpcUaSecurityTokenRequestType requestType;
  final OpcUaSecurityMode securityMode;
  final List<int>? clientNonce;
  final int requestedLifetime;

  const OpcUaOpenSecureChannelRequest({
    required this.header,
    this.clientProtocolVersion = 0,
    this.requestType = OpcUaSecurityTokenRequestType.issue,
    this.securityMode = OpcUaSecurityMode.none,
    this.clientNonce,
    this.requestedLifetime = 3600000, // 1 hour in ms
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    w.writeUint32(clientProtocolVersion);
    w.writeUint32(requestType.id);
    w.writeUint32(securityMode.id);
    w.writeByteStringOrNull(clientNonce);
    w.writeUint32(requestedLifetime);
  }

  factory OpcUaOpenSecureChannelRequest.decode(BinaryReader r) {
    return OpcUaOpenSecureChannelRequest(
      header: OpcUaRequestHeader.decode(r),
      clientProtocolVersion: r.readUint32(),
      requestType: OpcUaSecurityTokenRequestType.fromId(r.readUint32()),
      securityMode: OpcUaSecurityMode.fromId(r.readUint32()),
      clientNonce: r.readByteStringOrNull(),
      requestedLifetime: r.readUint32(),
    );
  }
}

class OpcUaOpenSecureChannelResponse {
  final OpcUaResponseHeader header;
  final int serverProtocolVersion;
  final OpcUaChannelSecurityToken securityToken;
  final List<int>? serverNonce;

  const OpcUaOpenSecureChannelResponse({
    required this.header,
    this.serverProtocolVersion = 0,
    required this.securityToken,
    this.serverNonce,
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    w.writeUint32(serverProtocolVersion);
    securityToken.encode(w);
    w.writeByteStringOrNull(serverNonce);
  }

  factory OpcUaOpenSecureChannelResponse.decode(BinaryReader r) {
    return OpcUaOpenSecureChannelResponse(
      header: OpcUaResponseHeader.decode(r),
      serverProtocolVersion: r.readUint32(),
      securityToken: OpcUaChannelSecurityToken.decode(r),
      serverNonce: r.readByteStringOrNull(),
    );
  }
}

class OpcUaCloseSecureChannelRequest {
  final OpcUaRequestHeader header;

  const OpcUaCloseSecureChannelRequest({required this.header});

  void encode(BinaryWriter w) => header.encode(w);

  factory OpcUaCloseSecureChannelRequest.decode(BinaryReader r) =>
      OpcUaCloseSecureChannelRequest(header: OpcUaRequestHeader.decode(r));
}

class OpcUaCloseSecureChannelResponse {
  final OpcUaResponseHeader header;

  const OpcUaCloseSecureChannelResponse({required this.header});

  void encode(BinaryWriter w) => header.encode(w);

  factory OpcUaCloseSecureChannelResponse.decode(BinaryReader r) =>
      OpcUaCloseSecureChannelResponse(header: OpcUaResponseHeader.decode(r));
}

const int _epochOffsetMicros = -11644473600000000;

int _dateTimeToTicks(DateTime dt) =>
    (dt.toUtc().microsecondsSinceEpoch - _epochOffsetMicros) * 10;

DateTime _ticksToDateTime(int ticks) =>
    DateTime.fromMicrosecondsSinceEpoch(
        (ticks ~/ 10) + _epochOffsetMicros, isUtc: true);
