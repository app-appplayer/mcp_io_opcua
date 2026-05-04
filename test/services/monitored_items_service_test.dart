import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:test/test.dart';

OpcUaRequestHeader _hdr({int handle = 1}) => OpcUaRequestHeader(
      authenticationToken:
          const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 0),
      timestamp: DateTime.utc(2026, 5, 3),
      requestHandle: handle,
    );

OpcUaResponseHeader _rhdr({int handle = 1}) => OpcUaResponseHeader(
      timestamp: DateTime.utc(2026, 5, 3),
      requestHandle: handle,
    );

void main() {
  group('OpcUaMonitoringParameters', () {
    test('TC-MP-001 defaults roundtrip — null filter, queueSize 1', () {
      final p = OpcUaMonitoringParameters(clientHandle: 17);
      final w = BinaryWriter();
      p.encode(w);
      final back =
          OpcUaMonitoringParameters.decode(BinaryReader(w.takeBytes()));
      expect(back.clientHandle, 17);
      expect(back.samplingInterval, -1);
      expect(back.filter.encoding, ExtensionObjectEncoding.noBody);
      expect(back.queueSize, 1);
      expect(back.discardOldest, isTrue);
    });

    test('TC-MP-002 sampling interval + queueSize + discardOldest preserved',
        () {
      final p = OpcUaMonitoringParameters(
        clientHandle: 1,
        samplingInterval: 100,
        queueSize: 10,
        discardOldest: false,
      );
      final w = BinaryWriter();
      p.encode(w);
      final back =
          OpcUaMonitoringParameters.decode(BinaryReader(w.takeBytes()));
      expect(back.samplingInterval, 100);
      expect(back.queueSize, 10);
      expect(back.discardOldest, isFalse);
    });
  });

  group('CreateMonitoredItems', () {
    test('TC-CMI-001 request roundtrip with one item', () {
      final req = OpcUaCreateMonitoredItemsRequest(
        header: _hdr(),
        subscriptionId: 1,
        timestampsToReturn: OpcUaTimestampsToReturn.both,
        itemsToCreate: [
          OpcUaMonitoredItemCreateRequest(
            itemToMonitor: const OpcUaReadValueId(
              nodeId: OpcUaNodeIdNumeric(namespaceIndex: 2, identifier: 100),
              attributeId: OpcUaAttribute.value,
            ),
            monitoringMode: OpcUaMonitoringMode.reporting,
            requestedParameters: OpcUaMonitoringParameters(clientHandle: 1),
          ),
        ],
      );
      final w = BinaryWriter();
      req.encode(w);
      final back = OpcUaCreateMonitoredItemsRequest.decode(
          BinaryReader(w.takeBytes()));
      expect(back.subscriptionId, 1);
      expect(back.itemsToCreate, hasLength(1));
      expect(back.itemsToCreate[0].monitoringMode,
          OpcUaMonitoringMode.reporting);
    });

    test('TC-CMI-002 response per-row results roundtrip', () {
      final resp = OpcUaCreateMonitoredItemsResponse(
        header: _rhdr(),
        results: [
          OpcUaMonitoredItemCreateResult(
            statusCode: 0,
            monitoredItemId: 5,
            revisedSamplingInterval: 250,
            revisedQueueSize: 1,
          ),
        ],
      );
      final w = BinaryWriter();
      resp.encode(w);
      final back = OpcUaCreateMonitoredItemsResponse.decode(
          BinaryReader(w.takeBytes()));
      expect(back.results, hasLength(1));
      expect(back.results[0].monitoredItemId, 5);
      expect(back.results[0].revisedSamplingInterval, 250);
    });
  });

  group('DeleteMonitoredItems', () {
    test('TC-DMI-001 ids + per-row StatusCode roundtrip', () {
      final req = OpcUaDeleteMonitoredItemsRequest(
        header: _hdr(),
        subscriptionId: 7,
        monitoredItemIds: const [1, 2, 3],
      );
      final w = BinaryWriter();
      req.encode(w);
      final reqBack = OpcUaDeleteMonitoredItemsRequest.decode(
          BinaryReader(w.takeBytes()));
      expect(reqBack.subscriptionId, 7);
      expect(reqBack.monitoredItemIds, [1, 2, 3]);

      final resp = OpcUaDeleteMonitoredItemsResponse(
        header: _rhdr(),
        results: const [0, 0, 0x80AB0000],
      );
      final w2 = BinaryWriter();
      resp.encode(w2);
      final back = OpcUaDeleteMonitoredItemsResponse.decode(
          BinaryReader(w2.takeBytes()));
      expect(back.results, [0, 0, 0x80AB0000]);
    });
  });

  group('Subscription service NodeIds', () {
    test('TC-SN-003 well-known constants are stable', () {
      expect(kOpcUaNodeIdCreateSubscriptionRequest, 787);
      expect(kOpcUaNodeIdCreateSubscriptionResponse, 790);
      expect(kOpcUaNodeIdPublishRequest, 826);
      expect(kOpcUaNodeIdCreateMonitoredItemsRequest, 751);
      expect(kOpcUaNodeIdDeleteSubscriptionsRequest, 847);
    });
  });
}
