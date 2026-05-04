/// Loopback integration test for [TcpOpcUaByteTransport].
///
/// A `dart:io ServerSocket` echoes every received chunk back; the test
/// drives the byte transport against that loopback and asserts the
/// roundtrip behaviour.
@TestOn('vm')
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:mcp_io_opcua/io.dart';
import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:test/test.dart';

void main() {
  group('TcpOpcUaByteTransport loopback', () {
    late ServerSocket server;
    late int port;
    late StreamController<Uint8List> echoCtrl;

    setUp(() async {
      echoCtrl = StreamController<Uint8List>.broadcast();
      server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      port = server.port;
      server.listen((socket) {
        socket.listen(
          (chunk) {
            echoCtrl.add(chunk);
            socket.add(chunk);
          },
          onDone: () => socket.destroy(),
        );
      });
    });

    tearDown(() async {
      await echoCtrl.close();
      await server.close();
    });

    test('TC-TCP-001 fromEndpoint defaults to port 4840 on opc.tcp URIs', () {
      final t = TcpOpcUaByteTransport.fromEndpoint(
        Uri.parse('opc.tcp://example.com'),
      );
      expect(t.host, 'example.com');
      expect(t.port, 4840);
    });

    test('TC-TCP-002 fromEndpoint rejects non-opc.tcp scheme', () {
      expect(
        () => TcpOpcUaByteTransport.fromEndpoint(
          Uri.parse('https://example.com'),
        ),
        throwsArgumentError,
      );
    });

    test('TC-TCP-003 send + incoming roundtrip via loopback echo server',
        () async {
      final t = TcpOpcUaByteTransport(host: '127.0.0.1', port: port);
      await t.open();

      final received = <int>[];
      final sub = t.incoming.listen(received.addAll);

      await t.send([0x01, 0x02, 0x03, 0x04]);
      // Allow the server to echo and the client to receive.
      await Future<void>.delayed(const Duration(milliseconds: 50));

      expect(received, [0x01, 0x02, 0x03, 0x04]);
      await sub.cancel();
      await t.close();
    });

    test('TC-TCP-004 close after send is graceful', () async {
      final t = TcpOpcUaByteTransport(host: '127.0.0.1', port: port);
      await t.open();
      await t.send([0xAA]);
      await t.close();
      expect(t.isOpen, isFalse);
    });

    test('TC-TCP-005 send after close throws StateError', () async {
      final t = TcpOpcUaByteTransport(host: '127.0.0.1', port: port);
      await t.open();
      await t.close();
      expect(() => t.send([0]), throwsStateError);
    });
  });

  group('TcpOpcUaByteTransport orchestration via OpcUaProtocolSession',
      () {
    test('TC-TCP-006 OpcUaProtocolSession can drive raw HEL over TCP', () async {
      // Build a minimal mock server that responds to a HEL with an ACK.
      final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      // Don't actually run the OPC UA flow — just verify the transport
      // pumps bytes correctly through the session's open() path without
      // crashing.
      late Socket peer;
      final ackSent = Completer<void>();
      server.listen((socket) {
        peer = socket;
        socket.listen((_) async {
          // Reply with a minimal ACK frame.
          final ack = OpcUaAcknowledgeMessage(
            receiveBufferSize: 65535,
            sendBufferSize: 65535,
            maxMessageSize: 16777216,
            maxChunkCount: 0,
          ).encode();
          peer.add(ack);
          await peer.flush();
          if (!ackSent.isCompleted) ackSent.complete();
        });
      });

      final transport = TcpOpcUaByteTransport(
        host: '127.0.0.1', port: server.port,
      );
      final session = OpcUaProtocolSession(
        transport: transport,
        endpoint: Uri.parse('opc.tcp://localhost:${server.port}'),
        clientDescription: const OpcUaApplicationDescription(
          applicationUri: 'urn:test',
          productUri: 'urn:test:product',
          applicationName: OpcUaLocalizedText(text: 'Test'),
        ),
      );
      await session.open();
      final ack = await session.hello();
      expect(ack.receiveBufferSize, 65535);
      await ackSent.future;
      await session.close();
      await server.close();
    });
  });
}
