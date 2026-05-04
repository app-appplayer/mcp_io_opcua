import 'dart:typed_data';

import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:test/test.dart';

OpcUaVariantValue _roundtripVariant(OpcUaVariantValue v) {
  final w = BinaryWriter();
  VariantCodec.encode(w, v);
  return VariantCodec.decode(BinaryReader(w.takeBytes()));
}

void main() {
  group('NodeId codec - 5 encodings', () {
    test('TC-NID-001 TwoByte (ns=0, id<256)', () {
      final w = BinaryWriter();
      NodeIdCodec.encode(
          w, const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 84));
      final bytes = w.takeBytes();
      // Expect 2 bytes total: mask 0x00 + uint8 id.
      expect(bytes.length, 2);
      expect(bytes[0], 0x00);
      expect(bytes[1], 84);

      final decoded =
          NodeIdCodec.decode(BinaryReader(bytes)) as OpcUaNodeIdNumeric;
      expect(decoded.namespaceIndex, 0);
      expect(decoded.identifier, 84);
    });

    test('TC-NID-002 FourByte (ns<256, id<65536)', () {
      final w = BinaryWriter();
      NodeIdCodec.encode(
          w, const OpcUaNodeIdNumeric(namespaceIndex: 2, identifier: 1234));
      final decoded = NodeIdCodec.decode(BinaryReader(w.takeBytes()))
          as OpcUaNodeIdNumeric;
      expect(decoded.namespaceIndex, 2);
      expect(decoded.identifier, 1234);
    });

    test('TC-NID-003 Numeric (ns or id large)', () {
      final w = BinaryWriter();
      NodeIdCodec.encode(
          w,
          const OpcUaNodeIdNumeric(
              namespaceIndex: 1024, identifier: 0xFFFFFF));
      final decoded = NodeIdCodec.decode(BinaryReader(w.takeBytes()))
          as OpcUaNodeIdNumeric;
      expect(decoded.namespaceIndex, 1024);
      expect(decoded.identifier, 0xFFFFFF);
    });

    test('TC-NID-004 String identifier', () {
      final w = BinaryWriter();
      NodeIdCodec.encode(
          w,
          const OpcUaNodeIdString(
              namespaceIndex: 4, identifier: 'PLC1.MAIN.iCounter'));
      final decoded = NodeIdCodec.decode(BinaryReader(w.takeBytes()))
          as OpcUaNodeIdString;
      expect(decoded.namespaceIndex, 4);
      expect(decoded.identifier, 'PLC1.MAIN.iCounter');
    });

    test('TC-NID-005 Guid identifier', () {
      final guid = OpcUaGuid.fromString('72962B91-FA75-4AE6-8D28-B404DC7DAF63');
      final w = BinaryWriter();
      NodeIdCodec.encode(
          w, OpcUaNodeIdGuid(namespaceIndex: 3, identifier: guid));
      final decoded =
          NodeIdCodec.decode(BinaryReader(w.takeBytes())) as OpcUaNodeIdGuid;
      expect(decoded.namespaceIndex, 3);
      expect(decoded.identifier, guid);
    });

    test('TC-NID-006 ByteString identifier', () {
      final w = BinaryWriter();
      NodeIdCodec.encode(
        w,
        OpcUaNodeIdByteString(
            namespaceIndex: 5, identifier: <int>[0xDE, 0xAD, 0xBE, 0xEF]),
      );
      final decoded = NodeIdCodec.decode(BinaryReader(w.takeBytes()))
          as OpcUaNodeIdByteString;
      expect(decoded.namespaceIndex, 5);
      expect(decoded.identifier, equals(Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF])));
    });
  });

  group('Variant scalars - all primitive built-ins', () {
    test('TC-VAR-001 Boolean', () {
      final dec = _roundtripVariant(
          OpcUaVariantValue.scalar(OpcUaBuiltInType.boolean, true));
      expect(dec.value, isTrue);
    });

    test('TC-VAR-002 SByte / Byte', () {
      expect(
          _roundtripVariant(
              OpcUaVariantValue.scalar(OpcUaBuiltInType.sByte, -42)).value,
          -42);
      expect(
          _roundtripVariant(
              OpcUaVariantValue.scalar(OpcUaBuiltInType.byte, 200)).value,
          200);
    });

    test('TC-VAR-003 Int16 / UInt16', () {
      expect(
          _roundtripVariant(
              OpcUaVariantValue.scalar(OpcUaBuiltInType.int16, -32000))
              .value,
          -32000);
      expect(
          _roundtripVariant(
              OpcUaVariantValue.scalar(OpcUaBuiltInType.uInt16, 65000))
              .value,
          65000);
    });

    test('TC-VAR-004 Int32 / UInt32', () {
      expect(
          _roundtripVariant(
              OpcUaVariantValue.scalar(OpcUaBuiltInType.int32, -123456))
              .value,
          -123456);
      expect(
          _roundtripVariant(
              OpcUaVariantValue.scalar(OpcUaBuiltInType.uInt32, 4000000000))
              .value,
          4000000000);
    });

    test('TC-VAR-005 Int64 / UInt64', () {
      expect(
          _roundtripVariant(OpcUaVariantValue.scalar(
                  OpcUaBuiltInType.int64, -9007199254740992))
              .value,
          -9007199254740992);
    });

    test('TC-VAR-006 Float / Double', () {
      final f =
          _roundtripVariant(OpcUaVariantValue.scalar(OpcUaBuiltInType.float, 3.14))
              .value as double;
      expect(f, closeTo(3.14, 1e-5));
      final d = _roundtripVariant(OpcUaVariantValue.scalar(
              OpcUaBuiltInType.double_, 2.718281828459045))
          .value as double;
      expect(d, closeTo(2.718281828459045, 1e-12));
    });

    test('TC-VAR-007 String', () {
      final dec = _roundtripVariant(
          OpcUaVariantValue.scalar(OpcUaBuiltInType.string, 'Hello'));
      expect(dec.value, 'Hello');
    });

    test('TC-VAR-008 DateTime roundtrip preserves UTC instant', () {
      final original = DateTime.utc(2026, 5, 2, 12, 34, 56, 789);
      final dec = _roundtripVariant(
          OpcUaVariantValue.scalar(OpcUaBuiltInType.dateTime, original));
      expect(dec.value, original);
    });

    test('TC-VAR-009 Guid', () {
      final g = OpcUaGuid.fromString('72962B91-FA75-4AE6-8D28-B404DC7DAF63');
      final dec = _roundtripVariant(
          OpcUaVariantValue.scalar(OpcUaBuiltInType.guid, g));
      expect(dec.value, g);
    });

    test('TC-VAR-010 ByteString', () {
      final dec = _roundtripVariant(OpcUaVariantValue.scalar(
          OpcUaBuiltInType.byteString, <int>[0x01, 0x02, 0x03]));
      expect(dec.value, equals(<int>[0x01, 0x02, 0x03]));
    });

    test('TC-VAR-011 NodeId scalar', () {
      const nid = OpcUaNodeIdNumeric(namespaceIndex: 2, identifier: 42);
      final dec = _roundtripVariant(
          OpcUaVariantValue.scalar(OpcUaBuiltInType.nodeId, nid));
      expect(dec.value, nid);
    });

    test('TC-VAR-012 StatusCode', () {
      const sc = OpcUaStatusCode(0x80AB0000); // BadDataLost
      final dec = _roundtripVariant(
          OpcUaVariantValue.scalar(OpcUaBuiltInType.statusCode, sc));
      expect(dec.value, sc);
    });

    test('TC-VAR-013 QualifiedName', () {
      const qn = OpcUaQualifiedName(namespaceIndex: 2, name: 'BrowseName');
      final dec = _roundtripVariant(
          OpcUaVariantValue.scalar(OpcUaBuiltInType.qualifiedName, qn));
      expect(dec.value, qn);
    });

    test('TC-VAR-014 LocalizedText (mask 0/1/2/3)', () {
      const empty = OpcUaLocalizedText();
      const localeOnly = OpcUaLocalizedText(locale: 'en-US');
      const textOnly = OpcUaLocalizedText(text: 'hello');
      const both = OpcUaLocalizedText(locale: 'en-US', text: 'hello');
      for (final lt in [empty, localeOnly, textOnly, both]) {
        final dec = _roundtripVariant(
            OpcUaVariantValue.scalar(OpcUaBuiltInType.localizedText, lt));
        expect(dec.value, lt);
      }
    });
  });

  group('Variant arrays + matrix', () {
    test('TC-VAR-020 Int32 array roundtrip', () {
      final orig =
          OpcUaVariantValue.array(OpcUaBuiltInType.int32, [1, 2, 3, 4]);
      final dec = _roundtripVariant(orig);
      expect(dec.isArray, isTrue);
      expect(dec.value, equals([1, 2, 3, 4]));
    });

    test('TC-VAR-021 Empty array (length 0)', () {
      final orig = OpcUaVariantValue.array(OpcUaBuiltInType.int32, []);
      final dec = _roundtripVariant(orig);
      expect(dec.isArray, isTrue);
      expect((dec.value as List).length, 0);
    });

    test('TC-VAR-022 Matrix with 2 dims', () {
      final orig = OpcUaVariantValue.matrix(
          OpcUaBuiltInType.int32, [1, 2, 3, 4, 5, 6], [2, 3]);
      final dec = _roundtripVariant(orig);
      expect(dec.isMatrix, isTrue);
      expect(dec.dimensions, [2, 3]);
      expect(dec.value, equals([1, 2, 3, 4, 5, 6]));
    });

    test('TC-VAR-023 Empty variant (mask 0)', () {
      final w = BinaryWriter();
      VariantCodec.encode(w, OpcUaVariantValue.empty);
      expect(w.takeBytes(), equals([0]));
      final dec = VariantCodec.decode(BinaryReader([0]));
      expect(dec.isEmpty, isTrue);
    });
  });

  group('DataValue codec - mask combinations', () {
    test('TC-DV-001 value-only mask', () {
      final dv = OpcUaDataValue(
        value: OpcUaVariantValue.scalar(OpcUaBuiltInType.int32, 42),
      );
      final w = BinaryWriter();
      DataValueCodec.encode(w, dv);
      final decoded = DataValueCodec.decode(BinaryReader(w.takeBytes()));
      expect(decoded.value!.value, 42);
      expect(decoded.status, isNull);
    });

    test('TC-DV-002 value + status + sourceTimestamp', () {
      final ts = DateTime.utc(2026, 1, 1, 12);
      final dv = OpcUaDataValue(
        value: OpcUaVariantValue.scalar(OpcUaBuiltInType.double_, 1.5),
        status: const OpcUaStatusCode(0x40000000), // Uncertain
        sourceTimestamp: ts,
      );
      final w = BinaryWriter();
      DataValueCodec.encode(w, dv);
      final decoded = DataValueCodec.decode(BinaryReader(w.takeBytes()));
      expect((decoded.value!.value as double), closeTo(1.5, 1e-9));
      expect(decoded.status!.value, 0x40000000);
      expect(decoded.sourceTimestamp, ts);
      expect(decoded.serverTimestamp, isNull);
    });

    test('TC-DV-003 all flags set', () {
      // picoseconds fields are uint16 (Part 6 §5.2.2.17): 0..65535.
      final dv = OpcUaDataValue(
        value: OpcUaVariantValue.scalar(OpcUaBuiltInType.int32, 1),
        status: const OpcUaStatusCode(0),
        sourceTimestamp: DateTime.utc(2026, 1, 1),
        sourcePicoseconds: 12345,
        serverTimestamp: DateTime.utc(2026, 1, 1, 0, 0, 1),
        serverPicoseconds: 54321,
      );
      final w = BinaryWriter();
      DataValueCodec.encode(w, dv);
      final decoded = DataValueCodec.decode(BinaryReader(w.takeBytes()));
      expect(decoded.value!.value, 1);
      expect(decoded.sourcePicoseconds, 12345);
      expect(decoded.serverPicoseconds, 54321);
    });
  });

  group('ExtensionObject codec', () {
    test('TC-EXT-001 noBody', () {
      final eo = OpcUaExtensionObject(
        typeId: const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 0),
        encoding: ExtensionObjectEncoding.noBody,
      );
      final w = BinaryWriter();
      ExtensionObjectCodec.encode(w, eo);
      final decoded = ExtensionObjectCodec.decode(BinaryReader(w.takeBytes()));
      expect(decoded.encoding, ExtensionObjectEncoding.noBody);
      expect(decoded.body, isNull);
    });

    test('TC-EXT-002 byteString body', () {
      final body = Uint8List.fromList([1, 2, 3, 4]);
      final eo = OpcUaExtensionObject(
        typeId:
            const OpcUaNodeIdNumeric(namespaceIndex: 2, identifier: 100),
        encoding: ExtensionObjectEncoding.byteString,
        body: body,
      );
      final w = BinaryWriter();
      ExtensionObjectCodec.encode(w, eo);
      final decoded = ExtensionObjectCodec.decode(BinaryReader(w.takeBytes()));
      expect(decoded.encoding, ExtensionObjectEncoding.byteString);
      expect(decoded.body, equals(body));
    });

    test('TC-EXT-003 xmlElement body', () {
      final body = '<x>1</x>'.codeUnits;
      final eo = OpcUaExtensionObject(
        typeId:
            const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 256),
        encoding: ExtensionObjectEncoding.xmlElement,
        body: Uint8List.fromList(body),
      );
      final w = BinaryWriter();
      ExtensionObjectCodec.encode(w, eo);
      final decoded = ExtensionObjectCodec.decode(BinaryReader(w.takeBytes()));
      expect(decoded.encoding, ExtensionObjectEncoding.xmlElement);
      expect(String.fromCharCodes(decoded.body!), '<x>1</x>');
    });
  });

  group('BinaryReader/Writer primitives', () {
    test('TC-BIN-001 uint16 / int16 LE roundtrip', () {
      final w = BinaryWriter()
        ..writeUint16(0xABCD)
        ..writeInt16(-1);
      final r = BinaryReader(w.takeBytes());
      expect(r.readUint16(), 0xABCD);
      expect(r.readInt16(), -1);
    });

    test('TC-BIN-002 string null vs empty', () {
      final w = BinaryWriter()
        ..writeStringOrNull(null)
        ..writeStringOrNull('');
      final r = BinaryReader(w.takeBytes());
      expect(r.readStringOrNull(), isNull);
      expect(r.readStringOrNull(), '');
    });

    test('TC-BIN-003 grow buffer', () {
      final w = BinaryWriter(8);
      for (var i = 0; i < 100; i++) {
        w.writeUint8(i & 0xFF);
      }
      final bytes = w.takeBytes();
      expect(bytes.length, 100);
      expect(bytes.last, 99);
    });
  });
}
