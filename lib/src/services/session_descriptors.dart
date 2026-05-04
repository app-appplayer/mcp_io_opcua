/// Common descriptors used by Session services (Part 4 §7).
///
/// `ApplicationDescription`, `EndpointDescription`, `UserTokenPolicy`,
/// `SignatureData`, `SignedSoftwareCertificate` all live here so they can
/// be shared between request / response codecs.
library;

import '../encoding/binary_reader.dart';
import '../encoding/binary_writer.dart';
import '../encoding/built_in_types.dart';

enum OpcUaApplicationType {
  server(0),
  client(1),
  clientAndServer(2),
  discoveryServer(3);

  const OpcUaApplicationType(this.id);
  final int id;

  static OpcUaApplicationType fromId(int id) {
    if (id < 0 || id > 3) {
      throw ArgumentError.value(id, 'id', 'invalid ApplicationType');
    }
    return OpcUaApplicationType.values[id];
  }
}

enum OpcUaUserTokenType {
  anonymous(0),
  username(1),
  certificate(2),
  issuedToken(3);

  const OpcUaUserTokenType(this.id);
  final int id;

  static OpcUaUserTokenType fromId(int id) {
    if (id < 0 || id > 3) {
      throw ArgumentError.value(id, 'id', 'invalid UserTokenType');
    }
    return OpcUaUserTokenType.values[id];
  }
}

/// `ApplicationDescription` (Part 4 §7.1).
class OpcUaApplicationDescription {
  final String applicationUri;
  final String productUri;
  final OpcUaLocalizedText applicationName;
  final OpcUaApplicationType applicationType;
  final String? gatewayServerUri;
  final String? discoveryProfileUri;
  final List<String> discoveryUrls;

  const OpcUaApplicationDescription({
    required this.applicationUri,
    required this.productUri,
    required this.applicationName,
    this.applicationType = OpcUaApplicationType.client,
    this.gatewayServerUri,
    this.discoveryProfileUri,
    this.discoveryUrls = const [],
  });

  void encode(BinaryWriter w) {
    w.writeStringOrNull(applicationUri);
    w.writeStringOrNull(productUri);
    var ltMask = 0;
    if (applicationName.locale != null) ltMask |= 0x01;
    if (applicationName.text != null) ltMask |= 0x02;
    w.writeUint8(ltMask);
    if (applicationName.locale != null) {
      w.writeStringOrNull(applicationName.locale);
    }
    if (applicationName.text != null) {
      w.writeStringOrNull(applicationName.text);
    }
    w.writeUint32(applicationType.id);
    w.writeStringOrNull(gatewayServerUri);
    w.writeStringOrNull(discoveryProfileUri);
    if (discoveryUrls.isEmpty) {
      w.writeInt32(-1);
    } else {
      w.writeInt32(discoveryUrls.length);
      for (final u in discoveryUrls) {
        w.writeStringOrNull(u);
      }
    }
  }

  factory OpcUaApplicationDescription.decode(BinaryReader r) {
    final appUri = r.readStringOrNull() ?? '';
    final prodUri = r.readStringOrNull() ?? '';
    final ltMask = r.readUint8();
    String? locale;
    String? text;
    if ((ltMask & 0x01) != 0) locale = r.readStringOrNull();
    if ((ltMask & 0x02) != 0) text = r.readStringOrNull();
    final type = OpcUaApplicationType.fromId(r.readUint32());
    final gateway = r.readStringOrNull();
    final discProfile = r.readStringOrNull();
    final n = r.readInt32();
    final urls = <String>[];
    if (n > 0) {
      for (var i = 0; i < n; i++) {
        urls.add(r.readStringOrNull() ?? '');
      }
    }
    return OpcUaApplicationDescription(
      applicationUri: appUri,
      productUri: prodUri,
      applicationName: OpcUaLocalizedText(locale: locale, text: text),
      applicationType: type,
      gatewayServerUri: gateway,
      discoveryProfileUri: discProfile,
      discoveryUrls: urls,
    );
  }
}

/// `UserTokenPolicy` (Part 4 §7.37).
class OpcUaUserTokenPolicy {
  final String policyId;
  final OpcUaUserTokenType tokenType;
  final String? issuedTokenType;
  final String? issuerEndpointUrl;
  final String? securityPolicyUri;

  const OpcUaUserTokenPolicy({
    required this.policyId,
    required this.tokenType,
    this.issuedTokenType,
    this.issuerEndpointUrl,
    this.securityPolicyUri,
  });

  void encode(BinaryWriter w) {
    w.writeStringOrNull(policyId);
    w.writeUint32(tokenType.id);
    w.writeStringOrNull(issuedTokenType);
    w.writeStringOrNull(issuerEndpointUrl);
    w.writeStringOrNull(securityPolicyUri);
  }

  factory OpcUaUserTokenPolicy.decode(BinaryReader r) {
    return OpcUaUserTokenPolicy(
      policyId: r.readStringOrNull() ?? '',
      tokenType: OpcUaUserTokenType.fromId(r.readUint32()),
      issuedTokenType: r.readStringOrNull(),
      issuerEndpointUrl: r.readStringOrNull(),
      securityPolicyUri: r.readStringOrNull(),
    );
  }
}

/// `EndpointDescription` (Part 4 §7.10).
class OpcUaEndpointDescription {
  final String endpointUrl;
  final OpcUaApplicationDescription server;
  final List<int>? serverCertificate;
  final int securityMode; // OpcUaSecurityMode.id
  final String securityPolicyUri;
  final List<OpcUaUserTokenPolicy> userIdentityTokens;
  final String transportProfileUri;
  final int securityLevel;

  const OpcUaEndpointDescription({
    required this.endpointUrl,
    required this.server,
    this.serverCertificate,
    required this.securityMode,
    required this.securityPolicyUri,
    this.userIdentityTokens = const [],
    this.transportProfileUri =
        'http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary',
    this.securityLevel = 0,
  });

  void encode(BinaryWriter w) {
    w.writeStringOrNull(endpointUrl);
    server.encode(w);
    w.writeByteStringOrNull(serverCertificate);
    w.writeUint32(securityMode);
    w.writeStringOrNull(securityPolicyUri);
    if (userIdentityTokens.isEmpty) {
      w.writeInt32(-1);
    } else {
      w.writeInt32(userIdentityTokens.length);
      for (final t in userIdentityTokens) {
        t.encode(w);
      }
    }
    w.writeStringOrNull(transportProfileUri);
    w.writeUint8(securityLevel);
  }

  factory OpcUaEndpointDescription.decode(BinaryReader r) {
    final url = r.readStringOrNull() ?? '';
    final server = OpcUaApplicationDescription.decode(r);
    final cert = r.readByteStringOrNull();
    final mode = r.readUint32();
    final policy = r.readStringOrNull() ?? '';
    final n = r.readInt32();
    final tokens = <OpcUaUserTokenPolicy>[];
    if (n > 0) {
      for (var i = 0; i < n; i++) {
        tokens.add(OpcUaUserTokenPolicy.decode(r));
      }
    }
    final transport = r.readStringOrNull() ?? '';
    final level = r.readUint8();
    return OpcUaEndpointDescription(
      endpointUrl: url,
      server: server,
      serverCertificate: cert,
      securityMode: mode,
      securityPolicyUri: policy,
      userIdentityTokens: tokens,
      transportProfileUri: transport,
      securityLevel: level,
    );
  }
}

/// `SignatureData` (Part 4 §7.30).
class OpcUaSignatureData {
  final String? algorithm;
  final List<int>? signature;

  const OpcUaSignatureData({this.algorithm, this.signature});

  void encode(BinaryWriter w) {
    w.writeStringOrNull(algorithm);
    w.writeByteStringOrNull(signature);
  }

  factory OpcUaSignatureData.decode(BinaryReader r) {
    return OpcUaSignatureData(
      algorithm: r.readStringOrNull(),
      signature: r.readByteStringOrNull(),
    );
  }
}

/// `SignedSoftwareCertificate` (Part 4 §7.33).
class OpcUaSignedSoftwareCertificate {
  final List<int>? certificateData;
  final List<int>? signature;

  const OpcUaSignedSoftwareCertificate({
    this.certificateData,
    this.signature,
  });

  void encode(BinaryWriter w) {
    w.writeByteStringOrNull(certificateData);
    w.writeByteStringOrNull(signature);
  }

  factory OpcUaSignedSoftwareCertificate.decode(BinaryReader r) {
    return OpcUaSignedSoftwareCertificate(
      certificateData: r.readByteStringOrNull(),
      signature: r.readByteStringOrNull(),
    );
  }
}
