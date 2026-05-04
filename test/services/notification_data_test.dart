import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:test/test.dart';

void main() {
  group('OpcUaMonitoredItemNotification', () {
    test('TC-MIN-001 roundtrip: clientHandle + DataValue', () {
      final n = OpcUaMonitoredItemNotification(
        clientHandle: 7,
        value: OpcUaDataValue(
          value: OpcUaVariantValue.scalar(OpcUaBuiltInType.double_, 23.5),
          status: OpcUaStatusCode.good,
        ),
      );
      final w = BinaryWriter();
      n.encode(w);
      final back =
          OpcUaMonitoredItemNotification.decode(BinaryReader(w.takeBytes()));
      expect(back.clientHandle, 7);
      expect(back.value.value!.value, 23.5);
    });
  });

  group('OpcUaDataChangeNotification', () {
    test('TC-DCN-001 roundtrip with two monitored items', () {
      final n = OpcUaDataChangeNotification(
        monitoredItems: [
          OpcUaMonitoredItemNotification(
            clientHandle: 1,
            value: OpcUaDataValue(
              value: OpcUaVariantValue.scalar(OpcUaBuiltInType.int32, 42),
            ),
          ),
          OpcUaMonitoredItemNotification(
            clientHandle: 2,
            value: OpcUaDataValue(
              value: OpcUaVariantValue.scalar(OpcUaBuiltInType.boolean, true),
            ),
          ),
        ],
      );
      final w = BinaryWriter();
      n.encode(w);
      final back =
          OpcUaDataChangeNotification.decode(BinaryReader(w.takeBytes()));
      expect(back.monitoredItems, hasLength(2));
      expect(back.monitoredItems[0].clientHandle, 1);
      expect(back.monitoredItems[0].value.value!.value, 42);
      expect(back.monitoredItems[1].value.value!.value, isTrue);
    });

    test('TC-DCN-002 toExtensionObject + fromExtension preserves contents',
        () {
      final n = OpcUaDataChangeNotification(
        monitoredItems: [
          OpcUaMonitoredItemNotification(
            clientHandle: 99,
            value: OpcUaDataValue(
              value:
                  OpcUaVariantValue.scalar(OpcUaBuiltInType.string, 'hello'),
            ),
          ),
        ],
      );
      final eo = n.toExtensionObject();
      expect(eo.typeId,
          const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 811));
      final back = OpcUaDataChangeNotification.fromExtension(eo);
      expect(back.monitoredItems.first.clientHandle, 99);
      expect(back.monitoredItems.first.value.value!.value, 'hello');
    });

    test('TC-DCN-003 fromExtension rejects wrong typeId', () {
      final eo = OpcUaEventNotificationList(events: const [])
          .toExtensionObject();
      expect(
        () => OpcUaDataChangeNotification.fromExtension(eo),
        throwsArgumentError,
      );
    });

    test('TC-DCN-004 round-trip empty monitoredItems list', () {
      const n = OpcUaDataChangeNotification(monitoredItems: []);
      final w = BinaryWriter();
      n.encode(w);
      final back =
          OpcUaDataChangeNotification.decode(BinaryReader(w.takeBytes()));
      expect(back.monitoredItems, isEmpty);
    });
  });

  group('OpcUaEventNotificationList', () {
    test('TC-ENL-001 roundtrip with two events of mixed field shapes', () {
      final l = OpcUaEventNotificationList(
        events: [
          OpcUaEventFieldList(
            clientHandle: 10,
            eventFields: [
              OpcUaVariantValue.scalar(OpcUaBuiltInType.string, 'AlarmA'),
              OpcUaVariantValue.scalar(OpcUaBuiltInType.int32, 700),
            ],
          ),
          OpcUaEventFieldList(
            clientHandle: 11,
            eventFields: const [],
          ),
        ],
      );
      final w = BinaryWriter();
      l.encode(w);
      final back =
          OpcUaEventNotificationList.decode(BinaryReader(w.takeBytes()));
      expect(back.events, hasLength(2));
      expect(back.events[0].clientHandle, 10);
      expect(back.events[0].eventFields, hasLength(2));
      expect(back.events[0].eventFields[0].value, 'AlarmA');
      expect(back.events[1].eventFields, isEmpty);
    });

    test('TC-ENL-002 ExtensionObject typeId is 916', () {
      final eo =
          OpcUaEventNotificationList(events: const []).toExtensionObject();
      expect(eo.typeId,
          const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 916));
    });
  });

  group('OpcUaStatusChangeNotification', () {
    test('TC-SCN-001 roundtrip with status code', () {
      const n = OpcUaStatusChangeNotification(status: 0x002F0000);
      final eo = n.toExtensionObject();
      expect(eo.typeId,
          const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 821));
      final back = OpcUaStatusChangeNotification.fromExtension(eo);
      expect(back.status, 0x002F0000);
    });
  });

  group('NodeId constants', () {
    test('TC-NID-001 notification typeIds match Part 4 §A.2', () {
      expect(kOpcUaNodeIdDataChangeNotification, 811);
      expect(kOpcUaNodeIdMonitoredItemNotification, 808);
      expect(kOpcUaNodeIdEventNotificationList, 916);
      expect(kOpcUaNodeIdEventFieldList, 919);
      expect(kOpcUaNodeIdStatusChangeNotification, 821);
    });
  });
}
