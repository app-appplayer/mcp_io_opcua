import 'dart:typed_data';

import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:test/test.dart';

OpcUaRequestHeader _hdr() => OpcUaRequestHeader(
      authenticationToken:
          const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 0),
      timestamp: DateTime.utc(2026, 5, 3),
      requestHandle: 1,
    );

OpcUaResponseHeader _rhdr() => OpcUaResponseHeader(
      timestamp: DateTime.utc(2026, 5, 3),
      requestHandle: 1,
    );

void main() {
  group('OpcUaApplicationDescription', () {
    test('TC-AD-001 roundtrip with full fields', () {
      const desc = OpcUaApplicationDescription(
        applicationUri: 'urn:test:client',
        productUri: 'urn:test:product',
        applicationName: OpcUaLocalizedText(locale: 'en', text: 'Test'),
        applicationType: OpcUaApplicationType.client,
        discoveryUrls: ['opc.tcp://server:4840'],
      );
      final w = BinaryWriter();
      desc.encode(w);
      final back =
          OpcUaApplicationDescription.decode(BinaryReader(w.takeBytes()));
      expect(back.applicationUri, 'urn:test:client');
      expect(back.applicationName.text, 'Test');
      expect(back.applicationType, OpcUaApplicationType.client);
      expect(back.discoveryUrls, ['opc.tcp://server:4840']);
    });

    test('TC-AD-002 empty discoveryUrls encodes -1 length', () {
      const desc = OpcUaApplicationDescription(
        applicationUri: 'urn:c',
        productUri: 'urn:p',
        applicationName: OpcUaLocalizedText(text: 'C'),
      );
      final w = BinaryWriter();
      desc.encode(w);
      final back =
          OpcUaApplicationDescription.decode(BinaryReader(w.takeBytes()));
      expect(back.discoveryUrls, isEmpty);
    });
  });

  group('OpcUaUserTokenPolicy + EndpointDescription', () {
    test('TC-UT-001 anonymous policy roundtrip', () {
      const policy = OpcUaUserTokenPolicy(
        policyId: 'anonymous',
        tokenType: OpcUaUserTokenType.anonymous,
      );
      final w = BinaryWriter();
      policy.encode(w);
      final back = OpcUaUserTokenPolicy.decode(BinaryReader(w.takeBytes()));
      expect(back.policyId, 'anonymous');
      expect(back.tokenType, OpcUaUserTokenType.anonymous);
    });

    test('TC-EP-001 EndpointDescription roundtrip', () {
      final ep = OpcUaEndpointDescription(
        endpointUrl: 'opc.tcp://localhost:4840',
        server: const OpcUaApplicationDescription(
          applicationUri: 'urn:server',
          productUri: 'urn:server-product',
          applicationName: OpcUaLocalizedText(text: 'Server'),
          applicationType: OpcUaApplicationType.server,
        ),
        securityMode: OpcUaSecurityMode.none.id,
        securityPolicyUri: kOpcUaSecurityPolicyNoneUri,
        userIdentityTokens: const [
          OpcUaUserTokenPolicy(
            policyId: 'anonymous',
            tokenType: OpcUaUserTokenType.anonymous,
          ),
        ],
      );
      final w = BinaryWriter();
      ep.encode(w);
      final back =
          OpcUaEndpointDescription.decode(BinaryReader(w.takeBytes()));
      expect(back.endpointUrl, 'opc.tcp://localhost:4840');
      expect(back.securityPolicyUri, kOpcUaSecurityPolicyNoneUri);
      expect(back.userIdentityTokens, hasLength(1));
      expect(back.userIdentityTokens[0].policyId, 'anonymous');
    });
  });

  group('OpcUaCreateSession', () {
    test('TC-CSS-001 request roundtrip', () {
      final req = OpcUaCreateSessionRequest(
        header: _hdr(),
        clientDescription: const OpcUaApplicationDescription(
          applicationUri: 'urn:c', productUri: 'urn:p',
          applicationName: OpcUaLocalizedText(text: 'C'),
        ),
        endpointUrl: 'opc.tcp://localhost:4840',
        sessionName: 'TestSession',
      );
      final w = BinaryWriter();
      req.encode(w);
      final back =
          OpcUaCreateSessionRequest.decode(BinaryReader(w.takeBytes()));
      expect(back.endpointUrl, 'opc.tcp://localhost:4840');
      expect(back.sessionName, 'TestSession');
      expect(back.requestedSessionTimeout, 1200000);
    });

    test('TC-CSS-002 response roundtrip with sessionId + auth token', () {
      final resp = OpcUaCreateSessionResponse(
        header: _rhdr(),
        sessionId:
            const OpcUaNodeIdNumeric(namespaceIndex: 1, identifier: 100),
        authenticationToken:
            const OpcUaNodeIdNumeric(namespaceIndex: 1, identifier: 200),
        revisedSessionTimeout: 600000,
        serverNonce: const [0xAA, 0xBB],
      );
      final w = BinaryWriter();
      resp.encode(w);
      final back =
          OpcUaCreateSessionResponse.decode(BinaryReader(w.takeBytes()));
      expect(back.sessionId,
          const OpcUaNodeIdNumeric(namespaceIndex: 1, identifier: 100));
      expect(back.authenticationToken,
          const OpcUaNodeIdNumeric(namespaceIndex: 1, identifier: 200));
      expect(back.revisedSessionTimeout, 600000);
      expect(back.serverNonce, [0xAA, 0xBB]);
    });
  });

  group('OpcUaActivateSession', () {
    test('TC-AS-001 request with anonymous identity token roundtrip', () {
      // Build the anonymous token body and wrap as ExtensionObject (typeId 321).
      final body = BinaryWriter();
      const OpcUaAnonymousIdentityToken(policyId: 'anonymous').encode(body);
      final identity = OpcUaExtensionObject(
        typeId: const OpcUaNodeIdNumeric(
          namespaceIndex: 0,
          identifier: kOpcUaNodeIdAnonymousIdentityToken,
        ),
        encoding: ExtensionObjectEncoding.byteString,
        body: Uint8List.fromList(body.takeBytes()),
      );
      final req = OpcUaActivateSessionRequest(
        header: _hdr(),
        userIdentityToken: identity,
        localeIds: const ['en-US'],
      );
      final w = BinaryWriter();
      req.encode(w);
      final back =
          OpcUaActivateSessionRequest.decode(BinaryReader(w.takeBytes()));
      expect(back.localeIds, ['en-US']);
      expect(back.userIdentityToken.encoding,
          ExtensionObjectEncoding.byteString);
      // Decode the anonymous body inside.
      final anon = OpcUaAnonymousIdentityToken.decode(
        BinaryReader(back.userIdentityToken.body!),
      );
      expect(anon.policyId, 'anonymous');
    });

    test('TC-AS-002 response with serverNonce + per-token results', () {
      final resp = OpcUaActivateSessionResponse(
        header: _rhdr(),
        serverNonce: const [0, 1, 2, 3],
        results: const [0],
      );
      final w = BinaryWriter();
      resp.encode(w);
      final back =
          OpcUaActivateSessionResponse.decode(BinaryReader(w.takeBytes()));
      expect(back.serverNonce, [0, 1, 2, 3]);
      expect(back.results, [0]);
    });
  });

  group('OpcUaCloseSession', () {
    test('TC-CS-001 request + response roundtrip', () {
      final req = OpcUaCloseSessionRequest(header: _hdr());
      final w = BinaryWriter();
      req.encode(w);
      final back =
          OpcUaCloseSessionRequest.decode(BinaryReader(w.takeBytes()));
      expect(back.deleteSubscriptions, isTrue);

      final resp = OpcUaCloseSessionResponse(header: _rhdr());
      final w2 = BinaryWriter();
      resp.encode(w2);
      final rb =
          OpcUaCloseSessionResponse.decode(BinaryReader(w2.takeBytes()));
      expect(rb.header.requestHandle, 1);
    });
  });
}
