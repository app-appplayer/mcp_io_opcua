import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:test/test.dart';

void main() {
  group('OpcUaWriteValue', () {
    test('TC-WV-001 roundtrip: numeric NodeId + Value attr + double', () {
      final v = OpcUaWriteValue(
        nodeId: const OpcUaNodeIdNumeric(namespaceIndex: 2, identifier: 1),
        attributeId: OpcUaAttribute.value,
        value: OpcUaDataValue(
          value: OpcUaVariantValue.scalar(OpcUaBuiltInType.double_, 3.14),
        ),
      );
      final w = BinaryWriter();
      v.encode(w);
      final back = OpcUaWriteValue.decode(BinaryReader(w.takeBytes()));
      expect(back.nodeId,
          const OpcUaNodeIdNumeric(namespaceIndex: 2, identifier: 1));
      expect(back.attributeId, OpcUaAttribute.value);
      expect(back.value.value!.type, OpcUaBuiltInType.double_);
      expect(back.value.value!.value, 3.14);
    });

    test('TC-WV-002 indexRange preserved', () {
      final v = OpcUaWriteValue(
        nodeId: const OpcUaNodeIdString(namespaceIndex: 3, identifier: 'Arr'),
        attributeId: OpcUaAttribute.value,
        indexRange: '0:9',
        value: OpcUaDataValue(
          value: OpcUaVariantValue.scalar(OpcUaBuiltInType.int32, 42),
        ),
      );
      final w = BinaryWriter();
      v.encode(w);
      final back = OpcUaWriteValue.decode(BinaryReader(w.takeBytes()));
      expect(back.indexRange, '0:9');
      expect(back.value.value!.value, 42);
    });
  });

  group('OpcUaWriteRequest / Response', () {
    test('TC-WR-001 request roundtrips with two write values', () {
      final header = OpcUaRequestHeader(
        authenticationToken:
            const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 0),
        timestamp: DateTime.utc(2026, 5, 3),
        requestHandle: 11,
      );
      final req = OpcUaWriteRequest(
        header: header,
        nodesToWrite: [
          OpcUaWriteValue(
            nodeId: const OpcUaNodeIdNumeric(namespaceIndex: 1, identifier: 1),
            attributeId: OpcUaAttribute.value,
            value: OpcUaDataValue(
              value: OpcUaVariantValue.scalar(OpcUaBuiltInType.boolean, true),
            ),
          ),
          OpcUaWriteValue(
            nodeId: const OpcUaNodeIdNumeric(namespaceIndex: 1, identifier: 2),
            attributeId: OpcUaAttribute.value,
            value: OpcUaDataValue(
              value: OpcUaVariantValue.scalar(OpcUaBuiltInType.string, 'hi'),
            ),
          ),
        ],
      );
      final w = BinaryWriter();
      req.encode(w);
      final back = OpcUaWriteRequest.decode(BinaryReader(w.takeBytes()));
      expect(back.nodesToWrite, hasLength(2));
      expect(back.nodesToWrite[0].value.value!.value, true);
      expect(back.nodesToWrite[1].value.value!.value, 'hi');
    });

    test('TC-WR-002 response carries per-row StatusCodes', () {
      final header = OpcUaResponseHeader(
        timestamp: DateTime.utc(2026, 5, 3),
        requestHandle: 11,
      );
      final resp = OpcUaWriteResponse(
        header: header,
        results: const [0, 0x80870000], // BadNoMatch on row 1
      );
      final w = BinaryWriter();
      resp.encode(w);
      final back = OpcUaWriteResponse.decode(BinaryReader(w.takeBytes()));
      expect(back.results, [0, 0x80870000]);
      expect(back.diagnosticInfoMasks, isEmpty);
    });
  });

  group('Service NodeIds', () {
    test('TC-SN-001 well-known constants are stable', () {
      expect(kOpcUaNodeIdReadRequest, 631);
      expect(kOpcUaNodeIdReadResponse, 634);
      expect(kOpcUaNodeIdWriteRequest, 673);
      expect(kOpcUaNodeIdWriteResponse, 676);
      expect(kOpcUaNodeIdBrowseRequest, 527);
      expect(kOpcUaNodeIdCallRequest, 712);
      expect(kOpcUaNodeIdHistoryReadRequest, 664);
    });

    test('TC-SN-002 OpcUaAttribute.value is 13 (Part 6 §A.1)', () {
      expect(OpcUaAttribute.value, 13);
      expect(OpcUaAttribute.nodeId, 1);
      expect(OpcUaAttribute.executable, 21);
    });
  });
}
