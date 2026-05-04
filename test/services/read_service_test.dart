import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:test/test.dart';

void main() {
  group('OpcUaReadValueId', () {
    test('TC-RV-001 roundtrip: numeric NodeId, Value attribute, no index range',
        () {
      const node = OpcUaNodeIdNumeric(namespaceIndex: 2, identifier: 1001);
      const rv = OpcUaReadValueId(
        nodeId: node, attributeId: OpcUaAttribute.value,
      );
      final w = BinaryWriter();
      rv.encode(w);
      final r = BinaryReader(w.takeBytes());
      final back = OpcUaReadValueId.decode(r);
      expect(back.nodeId, node);
      expect(back.attributeId, OpcUaAttribute.value);
      expect(back.indexRange, '');
      expect(back.dataEncoding.name, '');
      expect(back.dataEncoding.namespaceIndex, 0);
    });

    test('TC-RV-002 string NodeId + indexRange + dataEncoding qname', () {
      const node = OpcUaNodeIdString(namespaceIndex: 3, identifier: 'Temp.A1');
      const rv = OpcUaReadValueId(
        nodeId: node,
        attributeId: OpcUaAttribute.displayName,
        indexRange: '0:10',
        dataEncoding: OpcUaQualifiedName(
          namespaceIndex: 0, name: 'Default Binary',
        ),
      );
      final w = BinaryWriter();
      rv.encode(w);
      final back = OpcUaReadValueId.decode(BinaryReader(w.takeBytes()));
      expect(back.nodeId, node);
      expect(back.attributeId, OpcUaAttribute.displayName);
      expect(back.indexRange, '0:10');
      expect(back.dataEncoding.name, 'Default Binary');
    });
  });

  group('OpcUaReadRequest', () {
    test('TC-RR-001 roundtrip: header + 2 ReadValueIds', () {
      final header = OpcUaRequestHeader(
        authenticationToken:
            const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 0),
        timestamp: DateTime.utc(2026, 5, 3, 12, 0, 0),
        requestHandle: 7,
        timeoutHint: 5000,
      );
      final req = OpcUaReadRequest(
        header: header,
        maxAge: 0,
        timestampsToReturn: OpcUaTimestampsToReturn.both,
        nodesToRead: const [
          OpcUaReadValueId(
            nodeId: OpcUaNodeIdNumeric(namespaceIndex: 2, identifier: 1),
            attributeId: OpcUaAttribute.value,
          ),
          OpcUaReadValueId(
            nodeId: OpcUaNodeIdString(namespaceIndex: 2, identifier: 'X'),
            attributeId: OpcUaAttribute.value,
          ),
        ],
      );
      final w = BinaryWriter();
      req.encode(w);
      final back = OpcUaReadRequest.decode(BinaryReader(w.takeBytes()));
      expect(back.header.requestHandle, 7);
      expect(back.header.timeoutHint, 5000);
      expect(back.timestampsToReturn, OpcUaTimestampsToReturn.both);
      expect(back.nodesToRead, hasLength(2));
      expect(back.nodesToRead[1].nodeId,
          const OpcUaNodeIdString(namespaceIndex: 2, identifier: 'X'));
    });

    test('TC-RR-002 empty NodesToRead', () {
      final header = OpcUaRequestHeader(
        authenticationToken:
            const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 0),
        timestamp: DateTime.utc(2026, 5, 3),
        requestHandle: 1,
      );
      final req = OpcUaReadRequest(header: header, nodesToRead: const []);
      final w = BinaryWriter();
      req.encode(w);
      final back = OpcUaReadRequest.decode(BinaryReader(w.takeBytes()));
      expect(back.nodesToRead, isEmpty);
    });
  });

  group('OpcUaReadResponse', () {
    test('TC-RPR-001 roundtrip: 2 DataValue rows + null diagnostics', () {
      final header = OpcUaResponseHeader(
        timestamp: DateTime.utc(2026, 5, 3, 12, 0, 1),
        requestHandle: 7,
      );
      final resp = OpcUaReadResponse(
        header: header,
        results: [
          OpcUaDataValue(
            value: OpcUaVariantValue.scalar(OpcUaBuiltInType.double_, 21.5),
            status: OpcUaStatusCode.good,
            sourceTimestamp: DateTime.utc(2026, 5, 3, 12, 0, 1),
          ),
          OpcUaDataValue(
            value: OpcUaVariantValue.scalar(OpcUaBuiltInType.string, 'OK'),
          ),
        ],
      );
      final w = BinaryWriter();
      resp.encode(w);
      final back = OpcUaReadResponse.decode(BinaryReader(w.takeBytes()));
      expect(back.header.requestHandle, 7);
      expect(back.header.isGood, isTrue);
      expect(back.results, hasLength(2));
      final v0 = back.results[0].value!;
      expect(v0.type, OpcUaBuiltInType.double_);
      expect(v0.value, 21.5);
      final v1 = back.results[1].value!;
      expect(v1.type, OpcUaBuiltInType.string);
      expect(v1.value, 'OK');
      expect(back.diagnosticInfoMasks, isEmpty);
    });

    test('TC-RPR-002 service result encoded + roundtripped', () {
      final header = OpcUaResponseHeader(
        timestamp: DateTime.utc(2026, 5, 3),
        requestHandle: 1,
        serviceResult: 0x80AB0000, // BadInternalError-ish
      );
      final resp = OpcUaReadResponse(header: header, results: const []);
      final w = BinaryWriter();
      resp.encode(w);
      final back = OpcUaReadResponse.decode(BinaryReader(w.takeBytes()));
      expect(back.header.serviceResult, 0x80AB0000);
      expect(back.header.isGood, isFalse);
    });
  });
}
