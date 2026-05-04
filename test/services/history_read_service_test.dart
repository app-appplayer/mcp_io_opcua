import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:test/test.dart';

void main() {
  group('OpcUaHistoryReadValueId', () {
    test('TC-HV-001 roundtrip: nodeId + indexRange + null continuationPoint',
        () {
      const v = OpcUaHistoryReadValueId(
        nodeId: OpcUaNodeIdNumeric(namespaceIndex: 2, identifier: 5),
        indexRange: '0:99',
      );
      final w = BinaryWriter();
      v.encode(w);
      final back =
          OpcUaHistoryReadValueId.decode(BinaryReader(w.takeBytes()));
      expect(back.indexRange, '0:99');
      expect(back.continuationPoint, isNull);
    });

    test('TC-HV-002 continuationPoint preserved across roundtrip', () {
      const v = OpcUaHistoryReadValueId(
        nodeId: OpcUaNodeIdNumeric(namespaceIndex: 2, identifier: 5),
        continuationPoint: [0xDE, 0xAD, 0xBE, 0xEF],
      );
      final w = BinaryWriter();
      v.encode(w);
      final back =
          OpcUaHistoryReadValueId.decode(BinaryReader(w.takeBytes()));
      expect(back.continuationPoint, [0xDE, 0xAD, 0xBE, 0xEF]);
    });
  });

  group('OpcUaHistoryReadRequest', () {
    test('TC-HR-001 request roundtrip: empty details + 1 nodeToRead', () {
      final header = OpcUaRequestHeader(
        authenticationToken:
            const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 0),
        timestamp: DateTime.utc(2026, 5, 3),
        requestHandle: 1,
      );
      final req = OpcUaHistoryReadRequest(
        header: header,
        timestampsToReturn: OpcUaTimestampsToReturn.source,
        releaseContinuationPoints: false,
        nodesToRead: const [
          OpcUaHistoryReadValueId(
            nodeId: OpcUaNodeIdNumeric(namespaceIndex: 2, identifier: 9),
          ),
        ],
      );
      final w = BinaryWriter();
      req.encode(w);
      final back =
          OpcUaHistoryReadRequest.decode(BinaryReader(w.takeBytes()));
      expect(back.timestampsToReturn, OpcUaTimestampsToReturn.source);
      expect(back.releaseContinuationPoints, isFalse);
      expect(back.nodesToRead, hasLength(1));
      expect(back.historyReadDetails.encoding,
          ExtensionObjectEncoding.noBody);
    });

    test('TC-HR-002 releaseContinuationPoints toggle roundtrips', () {
      final header = OpcUaRequestHeader(
        authenticationToken:
            const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 0),
        timestamp: DateTime.utc(2026, 5, 3),
        requestHandle: 2,
      );
      final req = OpcUaHistoryReadRequest(
        header: header,
        releaseContinuationPoints: true,
        nodesToRead: const [],
      );
      final w = BinaryWriter();
      req.encode(w);
      final back =
          OpcUaHistoryReadRequest.decode(BinaryReader(w.takeBytes()));
      expect(back.releaseContinuationPoints, isTrue);
    });
  });

  group('OpcUaHistoryReadResponse', () {
    test('TC-HRP-001 response roundtrip: 1 result row with empty historyData',
        () {
      final header = OpcUaResponseHeader(
        timestamp: DateTime.utc(2026, 5, 3),
        requestHandle: 1,
      );
      final resp = OpcUaHistoryReadResponse(
        header: header,
        results: [OpcUaHistoryReadResultRow()],
      );
      final w = BinaryWriter();
      resp.encode(w);
      final back =
          OpcUaHistoryReadResponse.decode(BinaryReader(w.takeBytes()));
      expect(back.results, hasLength(1));
      expect(back.results[0].historyData.encoding,
          ExtensionObjectEncoding.noBody);
    });

    test('TC-HRP-002 continuationPoint preserved on the response row', () {
      final header = OpcUaResponseHeader(
        timestamp: DateTime.utc(2026, 5, 3),
        requestHandle: 1,
      );
      final resp = OpcUaHistoryReadResponse(
        header: header,
        results: [
          OpcUaHistoryReadResultRow(continuationPoint: const [0x01, 0x02]),
        ],
      );
      final w = BinaryWriter();
      resp.encode(w);
      final back =
          OpcUaHistoryReadResponse.decode(BinaryReader(w.takeBytes()));
      expect(back.results[0].continuationPoint, [0x01, 0x02]);
    });
  });
}
