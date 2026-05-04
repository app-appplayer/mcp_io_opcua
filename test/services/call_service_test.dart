import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:test/test.dart';

void main() {
  group('OpcUaCallMethodRequestRow', () {
    test('TC-CM-001 roundtrip: object + method + 2 inputs', () {
      final row = OpcUaCallMethodRequestRow(
        objectId: const OpcUaNodeIdNumeric(namespaceIndex: 2, identifier: 1),
        methodId: const OpcUaNodeIdNumeric(namespaceIndex: 2, identifier: 2),
        inputArguments: [
          OpcUaVariantValue.scalar(OpcUaBuiltInType.int32, 3),
          OpcUaVariantValue.scalar(OpcUaBuiltInType.int32, 4),
        ],
      );
      final w = BinaryWriter();
      row.encode(w);
      final back =
          OpcUaCallMethodRequestRow.decode(BinaryReader(w.takeBytes()));
      expect(back.inputArguments, hasLength(2));
      expect(back.inputArguments[0].value, 3);
      expect(back.inputArguments[1].value, 4);
    });
  });

  group('OpcUaCallMethodResultRow', () {
    test('TC-CR-001 roundtrip: status + 1 output', () {
      final row = OpcUaCallMethodResultRow(
        outputArguments: [
          OpcUaVariantValue.scalar(OpcUaBuiltInType.int32, 7),
        ],
      );
      final w = BinaryWriter();
      row.encode(w);
      final back =
          OpcUaCallMethodResultRow.decode(BinaryReader(w.takeBytes()));
      expect(back.statusCode, 0);
      expect(back.outputArguments, hasLength(1));
      expect(back.outputArguments[0].value, 7);
      expect(back.inputArgumentResults, isEmpty);
    });

    test('TC-CR-002 roundtrip with non-zero statusCode + per-input results',
        () {
      final row = OpcUaCallMethodResultRow(
        statusCode: 0x80AB0000,
        inputArgumentResults: const [0, 0x80870000],
      );
      final w = BinaryWriter();
      row.encode(w);
      final back =
          OpcUaCallMethodResultRow.decode(BinaryReader(w.takeBytes()));
      expect(back.statusCode, 0x80AB0000);
      expect(back.inputArgumentResults, [0, 0x80870000]);
    });
  });

  group('OpcUaCallRequest / Response', () {
    test('TC-CRQ-001 request + response roundtrip with one method', () {
      final reqHdr = OpcUaRequestHeader(
        authenticationToken:
            const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 0),
        timestamp: DateTime.utc(2026, 5, 3),
        requestHandle: 5,
      );
      final req = OpcUaCallRequest(
        header: reqHdr,
        methodsToCall: [
          OpcUaCallMethodRequestRow(
            objectId:
                const OpcUaNodeIdNumeric(namespaceIndex: 2, identifier: 1),
            methodId:
                const OpcUaNodeIdNumeric(namespaceIndex: 2, identifier: 2),
            inputArguments: [
              OpcUaVariantValue.scalar(OpcUaBuiltInType.int32, 10),
            ],
          ),
        ],
      );
      final w = BinaryWriter();
      req.encode(w);
      final reqBack = OpcUaCallRequest.decode(BinaryReader(w.takeBytes()));
      expect(reqBack.methodsToCall, hasLength(1));

      final respHdr = OpcUaResponseHeader(
        timestamp: DateTime.utc(2026, 5, 3),
        requestHandle: 5,
      );
      final resp = OpcUaCallResponse(
        header: respHdr,
        results: [
          OpcUaCallMethodResultRow(
            outputArguments: [
              OpcUaVariantValue.scalar(OpcUaBuiltInType.int32, 11),
            ],
          ),
        ],
      );
      final w2 = BinaryWriter();
      resp.encode(w2);
      final rb = OpcUaCallResponse.decode(BinaryReader(w2.takeBytes()));
      expect(rb.results, hasLength(1));
      expect(rb.results[0].outputArguments[0].value, 11);
    });
  });
}
