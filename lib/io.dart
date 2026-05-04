/// `dart:io`-only additions for `mcp_io_opcua`.
///
/// Importing the main `mcp_io_opcua` library keeps the package web-safe.
/// Importing this `io` library (only available on VM / Flutter desktop /
/// Flutter mobile / Flutter Linux/Windows/macOS) opts in to the
/// `dart:io` Socket-based byte transport.
///
/// ```dart
/// import 'package:mcp_io_opcua/mcp_io_opcua.dart';
/// import 'package:mcp_io_opcua/io.dart';
///
/// final transport = TcpOpcUaByteTransport.fromEndpoint(
///   Uri.parse('opc.tcp://localhost:4840'),
/// );
/// final session = OpcUaProtocolSession(
///   transport: transport,
///   endpoint: Uri.parse('opc.tcp://localhost:4840'),
///   clientDescription: ...,
/// );
/// await session.open();
/// await session.hello();
/// await session.openSecureChannel();
/// // ...
/// ```
library;

export 'src/session/tcp_byte_transport.dart';
export 'src/session/websocket_byte_transport.dart';
