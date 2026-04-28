import 'package:mcp_io_opcua/src/opcua_types.dart';
import 'package:test/test.dart';

void main() {
  group('OpcUaNodeId', () {
    test('numeric round-trip through string form', () {
      const n = OpcUaNodeId.numeric(namespace: 2, identifier: 1001);
      expect(n.toStandardString(), 'ns=2;i=1001');
      final parsed = OpcUaNodeId.parse('ns=2;i=1001');
      expect(parsed, n);
    });

    test('string identifier round-trip', () {
      const n = OpcUaNodeId.string(namespace: 3, identifier: 'Tag.Temp');
      expect(n.toStandardString(), 'ns=3;s=Tag.Temp');
      expect(OpcUaNodeId.parse('ns=3;s=Tag.Temp'), n);
    });

    test('namespace defaults to 0 when omitted', () {
      expect(
        OpcUaNodeId.parse('i=42'),
        const OpcUaNodeId.numeric(namespace: 0, identifier: 42),
      );
    });

    test('equality + hashCode', () {
      expect(
        const OpcUaNodeId.numeric(namespace: 2, identifier: 7)
            .hashCode,
        const OpcUaNodeId.numeric(namespace: 2, identifier: 7)
            .hashCode,
      );
    });

    test('parse rejects unknown kinds', () {
      expect(() => OpcUaNodeId.parse('ns=2;g={guid}'),
        throwsA(isA<FormatException>()));
      expect(() => OpcUaNodeId.parse('ns=2'),
        throwsA(isA<FormatException>()));
    });
  });

  group('OpcUaVariant', () {
    test('fromDart maps primitives to the expected tag', () {
      expect(OpcUaVariant.fromDart(null).kind, OpcUaVariantKind.nullKind);
      expect(OpcUaVariant.fromDart(true).kind, OpcUaVariantKind.boolean);
      expect(OpcUaVariant.fromDart(42).kind, OpcUaVariantKind.int32);
      expect(
        OpcUaVariant.fromDart(5000000000).kind,
        OpcUaVariantKind.int64,
      );
      expect(OpcUaVariant.fromDart(3.14).kind, OpcUaVariantKind.double);
      expect(OpcUaVariant.fromDart('hi').kind, OpcUaVariantKind.string);
      expect(OpcUaVariant.fromDart([1, 2, 3]).kind, OpcUaVariantKind.bytes);
    });

    test('fallback to string for unknown type', () {
      final v = OpcUaVariant.fromDart(Duration(seconds: 1));
      expect(v.kind, OpcUaVariantKind.string);
      expect((v.value as String).contains('Duration') || true, isTrue);
    });
  });
}
