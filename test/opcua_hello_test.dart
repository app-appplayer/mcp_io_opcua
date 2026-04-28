import 'package:mcp_io_opcua/src/opcua_hello.dart';
import 'package:mcp_io_opcua/src/opcua_types.dart';
import 'package:test/test.dart';

void main() {
  group('Hello message', () {
    test('round-trip preserves all fields', () {
      final m = OpcUaHelloMessage(
        protocolVersion: 0,
        receiveBufferSize: 65536,
        sendBufferSize: 65536,
        maxMessageSize: 16777216,
        maxChunkCount: 5000,
        endpointUrl: 'opc.tcp://server:4840/UA/Demo',
      );
      final decoded = OpcUaHelloMessage.decode(m.encode());
      expect(decoded.protocolVersion, 0);
      expect(decoded.receiveBufferSize, 65536);
      expect(decoded.sendBufferSize, 65536);
      expect(decoded.maxMessageSize, 16777216);
      expect(decoded.maxChunkCount, 5000);
      expect(decoded.endpointUrl, 'opc.tcp://server:4840/UA/Demo');
    });

    test('header layout begins with "HELF"', () {
      final bytes = OpcUaHelloMessage(
        receiveBufferSize: 0, sendBufferSize: 0,
        maxMessageSize: 0, maxChunkCount: 0, endpointUrl: '',
      ).encode();
      expect(String.fromCharCodes(bytes.sublist(0, 4)), 'HELF');
    });

    test('decode rejects truncated frame', () {
      expect(
        () => OpcUaHelloMessage.decode([1, 2, 3]),
        throwsA(isA<OpcUaProtocolError>()),
      );
    });

    test('decode rejects wrong message type', () {
      final ackBytes = OpcUaAcknowledgeMessage(
        receiveBufferSize: 0, sendBufferSize: 0,
        maxMessageSize: 0, maxChunkCount: 0,
      ).encode();
      expect(
        () => OpcUaHelloMessage.decode(ackBytes),
        throwsA(isA<OpcUaProtocolError>()),
      );
    });
  });

  group('Acknowledge message', () {
    test('round-trip preserves all fields', () {
      final m = OpcUaAcknowledgeMessage(
        receiveBufferSize: 65536,
        sendBufferSize: 65536,
        maxMessageSize: 16777216,
        maxChunkCount: 5000,
      );
      final decoded = OpcUaAcknowledgeMessage.decode(m.encode());
      expect(decoded.receiveBufferSize, 65536);
      expect(decoded.sendBufferSize, 65536);
      expect(decoded.maxMessageSize, 16777216);
      expect(decoded.maxChunkCount, 5000);
    });

    test('header layout begins with "ACKF"', () {
      final bytes = OpcUaAcknowledgeMessage(
        receiveBufferSize: 0, sendBufferSize: 0,
        maxMessageSize: 0, maxChunkCount: 0,
      ).encode();
      expect(String.fromCharCodes(bytes.sublist(0, 4)), 'ACKF');
    });
  });

  group('Error message', () {
    test('round-trip preserves error code + reason', () {
      const m = OpcUaErrorMessage(
        errorCode: 0x80A30000,
        reason: 'BadConnectionRejected',
      );
      final decoded = OpcUaErrorMessage.decode(m.encode());
      expect(decoded.errorCode, 0x80A30000);
      expect(decoded.reason, 'BadConnectionRejected');
    });

    test('empty reason decodes to empty string', () {
      const m = OpcUaErrorMessage(errorCode: 1, reason: '');
      final decoded = OpcUaErrorMessage.decode(m.encode());
      expect(decoded.reason, '');
    });
  });

  group('frame size validation', () {
    test('decoder rejects body shorter than declared size', () {
      final hello = OpcUaHelloMessage(
        receiveBufferSize: 0, sendBufferSize: 0,
        maxMessageSize: 0, maxChunkCount: 0,
        endpointUrl: 'opc.tcp://a',
      );
      final bytes = hello.encode().toList();
      // Truncate the frame artificially.
      final truncated = bytes.sublist(0, bytes.length - 3);
      expect(
        () => OpcUaHelloMessage.decode(truncated),
        throwsA(isA<OpcUaProtocolError>()),
      );
    });
  });
}
