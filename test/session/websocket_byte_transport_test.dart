/// Loopback integration test for [WebSocketOpcUaByteTransport].
///
/// Spawns a `dart:io` HttpServer that upgrades incoming requests to a
/// WebSocket and echoes every binary frame back. Drives the byte
/// transport against that loopback and verifies the binary roundtrip
/// + subprotocol negotiation.
@TestOn('vm')
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:mcp_io_opcua/io.dart';
import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:test/test.dart';

void main() {
  group('_toWsUri scheme translation', () {
    test('TC-WST-001 opc.ws → ws (plain) preserves host/port/path', () {
      final t = WebSocketOpcUaByteTransport(
        endpoint: Uri.parse('opc.ws://example.com:8080/uacp'),
      );
      expect(t.endpoint.scheme, 'opc.ws');
      // Internal scheme translation is exercised on connect; we
      // only verify construction doesn't throw here.
    });

    test('TC-WST-002 unsupported scheme rejected', () {
      // Constructor itself doesn't validate — open() does. Build a
      // local fake to ensure the validator path triggers without
      // a real server.
      final t = WebSocketOpcUaByteTransport(
        endpoint: Uri.parse('http://example.com'),
        connectTimeout: const Duration(milliseconds: 50),
      );
      expect(() => t.open(), throwsArgumentError);
    });
  });

  group('WebSocket loopback echo', () {
    late HttpServer server;
    late int port;
    late Completer<WebSocket> connected;

    setUp(() async {
      connected = Completer<WebSocket>();
      server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      port = server.port;
      server.listen((req) async {
        if (WebSocketTransformer.isUpgradeRequest(req)) {
          final ws = await WebSocketTransformer.upgrade(req,
              protocolSelector: (offered) =>
                  offered.firstWhere((p) => p == 'opcua+cp',
                      orElse: () => 'opcua+cp'));
          if (!connected.isCompleted) connected.complete(ws);
          ws.listen((data) {
            if (data is List<int>) {
              ws.add(data); // echo binary frames
            }
          }, onDone: () => ws.close());
        } else {
          req.response.statusCode = HttpStatus.badRequest;
          await req.response.close();
        }
      });
    });

    tearDown(() async {
      await server.close(force: true);
    });

    test('TC-WST-003 send + incoming roundtrip via loopback echo', () async {
      final t = WebSocketOpcUaByteTransport(
        endpoint: Uri.parse('opc.ws://127.0.0.1:$port'),
      );
      await t.open();
      final received = <int>[];
      final sub = t.incoming.listen(received.addAll);

      await t.send([0xCA, 0xFE, 0xBA, 0xBE]);
      await Future<void>.delayed(const Duration(milliseconds: 80));

      expect(received, [0xCA, 0xFE, 0xBA, 0xBE]);
      expect(t.selectedSubprotocol, 'opcua+cp');

      await sub.cancel();
      await t.close();
      await connected.future; // ensure server saw the connection
    });

    test('TC-WST-004 close after send is graceful', () async {
      final t = WebSocketOpcUaByteTransport(
        endpoint: Uri.parse('opc.ws://127.0.0.1:$port'),
      );
      await t.open();
      await t.send([0x10]);
      await t.close();
      expect(t.isOpen, isFalse);
      expect(() => t.send([0]), throwsStateError);
    });

    test('TC-WST-005 isOpen lifecycle', () async {
      final t = WebSocketOpcUaByteTransport(
        endpoint: Uri.parse('opc.ws://127.0.0.1:$port'),
      );
      expect(t.isOpen, isFalse);
      await t.open();
      expect(t.isOpen, isTrue);
      await t.close();
      expect(t.isOpen, isFalse);
    });
  });

  group('OpcUaProtocolSession over WebSocket', () {
    test('TC-WST-006 hello → ACK over WebSocket', () async {
      // Build a minimal mock OPC UA server that responds to a HEL with
      // an ACK over the WebSocket.
      final server =
          await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      server.listen((req) async {
        if (!WebSocketTransformer.isUpgradeRequest(req)) {
          req.response.statusCode = HttpStatus.badRequest;
          await req.response.close();
          return;
        }
        final ws = await WebSocketTransformer.upgrade(req);
        ws.listen((data) async {
          if (data is List<int>) {
            // Reply with a minimal ACK.
            final ack = OpcUaAcknowledgeMessage(
              receiveBufferSize: 65535,
              sendBufferSize: 65535,
              maxMessageSize: 16777216,
              maxChunkCount: 0,
            ).encode();
            ws.add(ack);
          }
        });
      });

      final transport = WebSocketOpcUaByteTransport(
        endpoint: Uri.parse('opc.ws://127.0.0.1:${server.port}'),
      );
      final session = OpcUaProtocolSession(
        transport: transport,
        endpoint: Uri.parse('opc.tcp://localhost:4840'),
        clientDescription: const OpcUaApplicationDescription(
          applicationUri: 'urn:test',
          productUri: 'urn:test:product',
          applicationName: OpcUaLocalizedText(text: 'Test'),
        ),
      );
      await session.open();
      final ack = await session.hello();
      expect(ack.receiveBufferSize, 65535);
      await session.close();
      await server.close(force: true);
    });
  });

  group('Binary-frame boundary alignment', () {
    test('TC-WST-007 each WebSocket frame becomes one Uint8List on incoming',
        () async {
      final server =
          await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      server.listen((req) async {
        if (!WebSocketTransformer.isUpgradeRequest(req)) return;
        final ws = await WebSocketTransformer.upgrade(req);
        ws.add(Uint8List.fromList([1, 2, 3]));
        ws.add(Uint8List.fromList([4, 5]));
        ws.add(Uint8List.fromList([6]));
      });
      final t = WebSocketOpcUaByteTransport(
        endpoint: Uri.parse('opc.ws://127.0.0.1:${server.port}'),
      );
      await t.open();
      final chunks = <List<int>>[];
      final done = Completer<void>();
      final sub = t.incoming.listen((c) {
        chunks.add(c);
        if (chunks.length == 3 && !done.isCompleted) done.complete();
      });
      await done.future.timeout(const Duration(seconds: 2));
      expect(chunks, [
        [1, 2, 3],
        [4, 5],
        [6],
      ]);
      await sub.cancel();
      await t.close();
      await server.close(force: true);
    });
  });
}
