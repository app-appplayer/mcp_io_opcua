/// Session service codecs (OPC UA Part 4 §5.6).
library;

import '../encoding/binary_reader.dart';
import '../encoding/binary_writer.dart';
import '../encoding/extension_object_codec.dart';
import '../encoding/node_id_codec.dart';
import 'request_header.dart';
import 'session_descriptors.dart';

class OpcUaCreateSessionRequest {
  final OpcUaRequestHeader header;
  final OpcUaApplicationDescription clientDescription;
  final String? serverUri;
  final String endpointUrl;
  final String sessionName;
  final List<int>? clientNonce;
  final List<int>? clientCertificate;

  /// Session timeout in ms.
  final double requestedSessionTimeout;

  final int maxResponseMessageSize;

  const OpcUaCreateSessionRequest({
    required this.header,
    required this.clientDescription,
    this.serverUri,
    required this.endpointUrl,
    required this.sessionName,
    this.clientNonce,
    this.clientCertificate,
    this.requestedSessionTimeout = 1200000,
    this.maxResponseMessageSize = 0,
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    clientDescription.encode(w);
    w.writeStringOrNull(serverUri);
    w.writeStringOrNull(endpointUrl);
    w.writeStringOrNull(sessionName);
    w.writeByteStringOrNull(clientNonce);
    w.writeByteStringOrNull(clientCertificate);
    w.writeFloat64(requestedSessionTimeout);
    w.writeUint32(maxResponseMessageSize);
  }

  factory OpcUaCreateSessionRequest.decode(BinaryReader r) {
    return OpcUaCreateSessionRequest(
      header: OpcUaRequestHeader.decode(r),
      clientDescription: OpcUaApplicationDescription.decode(r),
      serverUri: r.readStringOrNull(),
      endpointUrl: r.readStringOrNull() ?? '',
      sessionName: r.readStringOrNull() ?? '',
      clientNonce: r.readByteStringOrNull(),
      clientCertificate: r.readByteStringOrNull(),
      requestedSessionTimeout: r.readFloat64(),
      maxResponseMessageSize: r.readUint32(),
    );
  }
}

class OpcUaCreateSessionResponse {
  final OpcUaResponseHeader header;
  final OpcUaNodeIdValue sessionId;
  final OpcUaNodeIdValue authenticationToken;
  final double revisedSessionTimeout;
  final List<int>? serverNonce;
  final List<int>? serverCertificate;
  final List<OpcUaEndpointDescription> serverEndpoints;
  final List<OpcUaSignedSoftwareCertificate> serverSoftwareCertificates;
  final OpcUaSignatureData serverSignature;
  final int maxRequestMessageSize;

  const OpcUaCreateSessionResponse({
    required this.header,
    required this.sessionId,
    required this.authenticationToken,
    required this.revisedSessionTimeout,
    this.serverNonce,
    this.serverCertificate,
    this.serverEndpoints = const [],
    this.serverSoftwareCertificates = const [],
    this.serverSignature = const OpcUaSignatureData(),
    this.maxRequestMessageSize = 0,
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    NodeIdCodec.encode(w, sessionId);
    NodeIdCodec.encode(w, authenticationToken);
    w.writeFloat64(revisedSessionTimeout);
    w.writeByteStringOrNull(serverNonce);
    w.writeByteStringOrNull(serverCertificate);
    if (serverEndpoints.isEmpty) {
      w.writeInt32(-1);
    } else {
      w.writeInt32(serverEndpoints.length);
      for (final e in serverEndpoints) {
        e.encode(w);
      }
    }
    if (serverSoftwareCertificates.isEmpty) {
      w.writeInt32(-1);
    } else {
      w.writeInt32(serverSoftwareCertificates.length);
      for (final c in serverSoftwareCertificates) {
        c.encode(w);
      }
    }
    serverSignature.encode(w);
    w.writeUint32(maxRequestMessageSize);
  }

  factory OpcUaCreateSessionResponse.decode(BinaryReader r) {
    final header = OpcUaResponseHeader.decode(r);
    final sessionId = NodeIdCodec.decode(r);
    final authToken = NodeIdCodec.decode(r);
    final timeout = r.readFloat64();
    final serverNonce = r.readByteStringOrNull();
    final serverCert = r.readByteStringOrNull();
    final n = r.readInt32();
    final endpoints = <OpcUaEndpointDescription>[];
    if (n > 0) {
      for (var i = 0; i < n; i++) {
        endpoints.add(OpcUaEndpointDescription.decode(r));
      }
    }
    final scn = r.readInt32();
    final softCerts = <OpcUaSignedSoftwareCertificate>[];
    if (scn > 0) {
      for (var i = 0; i < scn; i++) {
        softCerts.add(OpcUaSignedSoftwareCertificate.decode(r));
      }
    }
    final sig = OpcUaSignatureData.decode(r);
    final maxReq = r.readUint32();
    return OpcUaCreateSessionResponse(
      header: header,
      sessionId: sessionId,
      authenticationToken: authToken,
      revisedSessionTimeout: timeout,
      serverNonce: serverNonce,
      serverCertificate: serverCert,
      serverEndpoints: endpoints,
      serverSoftwareCertificates: softCerts,
      serverSignature: sig,
      maxRequestMessageSize: maxReq,
    );
  }
}

class OpcUaActivateSessionRequest {
  final OpcUaRequestHeader header;
  final OpcUaSignatureData clientSignature;
  final List<OpcUaSignedSoftwareCertificate> clientSoftwareCertificates;
  final List<String> localeIds;
  final OpcUaExtensionObject userIdentityToken;
  final OpcUaSignatureData userTokenSignature;

  OpcUaActivateSessionRequest({
    required this.header,
    this.clientSignature = const OpcUaSignatureData(),
    this.clientSoftwareCertificates = const [],
    this.localeIds = const [],
    OpcUaExtensionObject? userIdentityToken,
    this.userTokenSignature = const OpcUaSignatureData(),
  }) : userIdentityToken = userIdentityToken ?? _nullToken;

  void encode(BinaryWriter w) {
    header.encode(w);
    clientSignature.encode(w);
    if (clientSoftwareCertificates.isEmpty) {
      w.writeInt32(-1);
    } else {
      w.writeInt32(clientSoftwareCertificates.length);
      for (final c in clientSoftwareCertificates) {
        c.encode(w);
      }
    }
    if (localeIds.isEmpty) {
      w.writeInt32(-1);
    } else {
      w.writeInt32(localeIds.length);
      for (final l in localeIds) {
        w.writeStringOrNull(l);
      }
    }
    ExtensionObjectCodec.encode(w, userIdentityToken);
    userTokenSignature.encode(w);
  }

  factory OpcUaActivateSessionRequest.decode(BinaryReader r) {
    final header = OpcUaRequestHeader.decode(r);
    final clientSig = OpcUaSignatureData.decode(r);
    final cn = r.readInt32();
    final softCerts = <OpcUaSignedSoftwareCertificate>[];
    if (cn > 0) {
      for (var i = 0; i < cn; i++) {
        softCerts.add(OpcUaSignedSoftwareCertificate.decode(r));
      }
    }
    final ln = r.readInt32();
    final locales = <String>[];
    if (ln > 0) {
      for (var i = 0; i < ln; i++) {
        locales.add(r.readStringOrNull() ?? '');
      }
    }
    final userToken = ExtensionObjectCodec.decode(r);
    final userSig = OpcUaSignatureData.decode(r);
    return OpcUaActivateSessionRequest(
      header: header,
      clientSignature: clientSig,
      clientSoftwareCertificates: softCerts,
      localeIds: locales,
      userIdentityToken: userToken,
      userTokenSignature: userSig,
    );
  }

  static final _nullToken = OpcUaExtensionObject(
    typeId: const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 0),
    encoding: ExtensionObjectEncoding.noBody,
  );
}

class OpcUaActivateSessionResponse {
  final OpcUaResponseHeader header;
  final List<int>? serverNonce;
  final List<int> results;
  final List<int> diagnosticInfoMasks;

  const OpcUaActivateSessionResponse({
    required this.header,
    this.serverNonce,
    this.results = const [],
    this.diagnosticInfoMasks = const [],
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    w.writeByteStringOrNull(serverNonce);
    if (results.isEmpty) {
      w.writeInt32(-1);
    } else {
      w.writeInt32(results.length);
      for (final c in results) {
        w.writeUint32(c);
      }
    }
    if (diagnosticInfoMasks.isEmpty) {
      w.writeInt32(-1);
    } else {
      w.writeInt32(diagnosticInfoMasks.length);
      for (final m in diagnosticInfoMasks) {
        w.writeUint8(m);
      }
    }
  }

  factory OpcUaActivateSessionResponse.decode(BinaryReader r) {
    final header = OpcUaResponseHeader.decode(r);
    final nonce = r.readByteStringOrNull();
    final rn = r.readInt32();
    final results = <int>[];
    if (rn > 0) {
      for (var i = 0; i < rn; i++) {
        results.add(r.readUint32());
      }
    }
    final dn = r.readInt32();
    final diag = <int>[];
    if (dn > 0) {
      for (var i = 0; i < dn; i++) {
        final m = r.readUint8();
        if (m != 0) {
          throw StateError(
            'OpcUaActivateSessionResponse: '
            'non-empty DiagnosticInfo not supported',
          );
        }
        diag.add(m);
      }
    }
    return OpcUaActivateSessionResponse(
      header: header,
      serverNonce: nonce,
      results: results,
      diagnosticInfoMasks: diag,
    );
  }
}

class OpcUaCloseSessionRequest {
  final OpcUaRequestHeader header;
  final bool deleteSubscriptions;

  const OpcUaCloseSessionRequest({
    required this.header,
    this.deleteSubscriptions = true,
  });

  void encode(BinaryWriter w) {
    header.encode(w);
    w.writeUint8(deleteSubscriptions ? 1 : 0);
  }

  factory OpcUaCloseSessionRequest.decode(BinaryReader r) {
    return OpcUaCloseSessionRequest(
      header: OpcUaRequestHeader.decode(r),
      deleteSubscriptions: r.readUint8() != 0,
    );
  }
}

class OpcUaCloseSessionResponse {
  final OpcUaResponseHeader header;

  const OpcUaCloseSessionResponse({required this.header});

  void encode(BinaryWriter w) => header.encode(w);

  factory OpcUaCloseSessionResponse.decode(BinaryReader r) =>
      OpcUaCloseSessionResponse(header: OpcUaResponseHeader.decode(r));
}

/// `AnonymousIdentityToken` body. Wrap into an `OpcUaExtensionObject` with
/// typeId `kOpcUaNodeIdAnonymousIdentityToken` (321) and
/// `ExtensionObjectEncoding.byteString` to use as the
/// `userIdentityToken` of an ActivateSession request.
class OpcUaAnonymousIdentityToken {
  final String policyId;

  const OpcUaAnonymousIdentityToken({this.policyId = ''});

  void encode(BinaryWriter w) {
    w.writeStringOrNull(policyId);
  }

  factory OpcUaAnonymousIdentityToken.decode(BinaryReader r) {
    return OpcUaAnonymousIdentityToken(policyId: r.readStringOrNull() ?? '');
  }
}
