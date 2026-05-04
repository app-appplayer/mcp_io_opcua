import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:test/test.dart';

void main() {
  group('OpcUaBrowseDescription', () {
    test('TC-BD-001 roundtrip: forward + all classes + all result mask', () {
      const desc = OpcUaBrowseDescription(
        nodeId: OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 84),
      );
      final w = BinaryWriter();
      desc.encode(w);
      final back = OpcUaBrowseDescription.decode(BinaryReader(w.takeBytes()));
      expect(back.nodeId,
          const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 84));
      expect(back.browseDirection, OpcUaBrowseDirection.both);
      expect(back.includeSubtypes, isTrue);
      expect(back.nodeClassMask, OpcUaNodeClass.unspecified);
      expect(back.resultMask, OpcUaBrowseResultMask.all);
    });

    test('TC-BD-002 roundtrip: inverse + variable nodeClass + custom mask', () {
      const desc = OpcUaBrowseDescription(
        nodeId: OpcUaNodeIdString(namespaceIndex: 2, identifier: 'Tag'),
        browseDirection: OpcUaBrowseDirection.inverse,
        includeSubtypes: false,
        nodeClassMask: OpcUaNodeClass.variable | OpcUaNodeClass.method,
        resultMask: OpcUaBrowseResultMask.browseName |
            OpcUaBrowseResultMask.displayName,
      );
      final w = BinaryWriter();
      desc.encode(w);
      final back = OpcUaBrowseDescription.decode(BinaryReader(w.takeBytes()));
      expect(back.browseDirection, OpcUaBrowseDirection.inverse);
      expect(back.includeSubtypes, isFalse);
      expect(back.nodeClassMask,
          OpcUaNodeClass.variable | OpcUaNodeClass.method);
    });
  });

  group('OpcUaReferenceDescriptionWire', () {
    test('TC-RD-001 roundtrip with QualifiedName + LocalizedText fields', () {
      final ref = OpcUaReferenceDescriptionWire(
        referenceTypeId:
            const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 35),
        isForward: true,
        nodeId: const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 85),
        browseName:
            const OpcUaQualifiedName(namespaceIndex: 0, name: 'Objects'),
        displayName: const OpcUaLocalizedText(locale: 'en', text: 'Objects'),
        nodeClass: OpcUaNodeClass.object,
        typeDefinition:
            const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 61),
      );
      final w = BinaryWriter();
      ref.encode(w);
      final back =
          OpcUaReferenceDescriptionWire.decode(BinaryReader(w.takeBytes()));
      expect(back.isForward, isTrue);
      expect(back.browseName.name, 'Objects');
      expect(back.displayName.locale, 'en');
      expect(back.displayName.text, 'Objects');
      expect(back.nodeClass, OpcUaNodeClass.object);
    });
  });

  group('OpcUaBrowseRequest / Response', () {
    test('TC-BR-001 request roundtrip with view + 1 description', () {
      final header = OpcUaRequestHeader(
        authenticationToken:
            const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 0),
        timestamp: DateTime.utc(2026, 5, 3),
        requestHandle: 1,
      );
      final req = OpcUaBrowseRequest(
        header: header,
        view: OpcUaViewDescription.nullView(),
        requestedMaxReferencesPerNode: 100,
        nodesToBrowse: const [
          OpcUaBrowseDescription(
            nodeId: OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 84),
          ),
        ],
      );
      final w = BinaryWriter();
      req.encode(w);
      final back = OpcUaBrowseRequest.decode(BinaryReader(w.takeBytes()));
      expect(back.requestedMaxReferencesPerNode, 100);
      expect(back.nodesToBrowse, hasLength(1));
      expect(back.view.viewVersion, 0);
    });

    test('TC-BR-002 response carries 2 result rows + null continuation', () {
      final header = OpcUaResponseHeader(
        timestamp: DateTime.utc(2026, 5, 3),
        requestHandle: 1,
      );
      final resp = OpcUaBrowseResponse(
        header: header,
        results: [
          OpcUaBrowseResultRow(
            references: [
              OpcUaReferenceDescriptionWire(
                referenceTypeId: const OpcUaNodeIdNumeric(
                    namespaceIndex: 0, identifier: 35),
                isForward: true,
                nodeId: const OpcUaNodeIdNumeric(
                    namespaceIndex: 0, identifier: 85),
                browseName: const OpcUaQualifiedName(
                    namespaceIndex: 0, name: 'Objects'),
                displayName:
                    const OpcUaLocalizedText(locale: null, text: 'Objects'),
                nodeClass: OpcUaNodeClass.object,
                typeDefinition: const OpcUaNodeIdNumeric(
                    namespaceIndex: 0, identifier: 61),
              ),
            ],
          ),
          const OpcUaBrowseResultRow(),
        ],
      );
      final w = BinaryWriter();
      resp.encode(w);
      final back = OpcUaBrowseResponse.decode(BinaryReader(w.takeBytes()));
      expect(back.results, hasLength(2));
      expect(back.results[0].references, hasLength(1));
      expect(back.results[0].references[0].browseName.name, 'Objects');
      expect(back.results[1].references, isEmpty);
      expect(back.results[1].continuationPoint, isNull);
    });
  });
}
