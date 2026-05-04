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
  group('OpcUaChannelSecurityToken', () {
    test('TC-CT-001 roundtrip', () {
      final t = OpcUaChannelSecurityToken(
        channelId: 1234,
        tokenId: 1,
        createdAt: DateTime.utc(2026, 5, 3, 12, 0, 0),
        revisedLifetime: 3600000,
      );
      final w = BinaryWriter();
      t.encode(w);
      final back =
          OpcUaChannelSecurityToken.decode(BinaryReader(w.takeBytes()));
      expect(back.channelId, 1234);
      expect(back.tokenId, 1);
      expect(back.revisedLifetime, 3600000);
    });
  });

  group('OpcUaOpenSecureChannelRequest / Response', () {
    test('TC-OPN-001 request roundtrip — None policy', () {
      final req = OpcUaOpenSecureChannelRequest(
        header: _hdr(),
        clientNonce: const [],
      );
      final w = BinaryWriter();
      req.encode(w);
      final back =
          OpcUaOpenSecureChannelRequest.decode(BinaryReader(w.takeBytes()));
      expect(back.requestType, OpcUaSecurityTokenRequestType.issue);
      expect(back.securityMode, OpcUaSecurityMode.none);
      expect(back.requestedLifetime, 3600000);
    });

    test('TC-OPN-002 response roundtrip with security token', () {
      final resp = OpcUaOpenSecureChannelResponse(
        header: _rhdr(),
        serverProtocolVersion: 0,
        securityToken: OpcUaChannelSecurityToken(
          channelId: 7,
          tokenId: 1,
          createdAt: DateTime.utc(2026, 5, 3),
          revisedLifetime: 3600000,
        ),
        serverNonce: const [0, 1, 2, 3],
      );
      final w = BinaryWriter();
      resp.encode(w);
      final back =
          OpcUaOpenSecureChannelResponse.decode(BinaryReader(w.takeBytes()));
      expect(back.securityToken.channelId, 7);
      expect(back.securityToken.tokenId, 1);
      expect(back.serverNonce, [0, 1, 2, 3]);
    });
  });

  group('OpcUaCloseSecureChannelRequest / Response', () {
    test('TC-CLO-001 request roundtrip', () {
      final req = OpcUaCloseSecureChannelRequest(header: _hdr());
      final w = BinaryWriter();
      req.encode(w);
      final back =
          OpcUaCloseSecureChannelRequest.decode(BinaryReader(w.takeBytes()));
      expect(back.header.requestHandle, 1);
    });

    test('TC-CLO-002 response roundtrip', () {
      final resp = OpcUaCloseSecureChannelResponse(header: _rhdr());
      final w = BinaryWriter();
      resp.encode(w);
      final back =
          OpcUaCloseSecureChannelResponse.decode(BinaryReader(w.takeBytes()));
      expect(back.header.requestHandle, 1);
    });
  });

  group('Service NodeIds', () {
    test('TC-SN-004 OPN/Session NodeId constants are stable', () {
      expect(kOpcUaNodeIdOpenSecureChannelRequest, 446);
      expect(kOpcUaNodeIdOpenSecureChannelResponse, 449);
      expect(kOpcUaNodeIdCreateSessionRequest, 461);
      expect(kOpcUaNodeIdActivateSessionRequest, 467);
      expect(kOpcUaNodeIdCloseSessionRequest, 473);
      expect(kOpcUaNodeIdAnonymousIdentityToken, 321);
    });
  });
}
