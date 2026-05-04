# mcp_io_opcua

OPC UA Binary adapter for [`mcp_io`](https://pub.dev/packages/mcp_io) —
industrial automation gateway integration with full service set
binary codecs, byte transport + frame pump, protocol-level session
orchestration, and a turnkey Subscription publish/ack loop.

## Capability matrix

| Area | Support |
|---|---|
| Wire framing | HEL / ACK / ERR (Part 6 §7.1.2), OPN / CLO / MSG with asymmetric + symmetric security headers + sequence header |
| Transport | dart:io TCP Socket (`lib/io.dart` opt-in entry); pluggable byte transport for tests / WebSocket / TLS layered above |
| Built-in types | All 25 (`Boolean`..`DiagnosticInfo`) + 5 NodeId encodings + DataValue + ExtensionObject |
| Service set | OpenSecureChannel / CloseSecureChannel · CreateSession / ActivateSession / CloseSession · Read · Write · Browse · CallMethod · HistoryRead · CreateSubscription / Modify / Delete / SetPublishingMode · CreateMonitoredItems / DeleteMonitoredItems · Publish / Republish |
| Notifications | `DataChangeNotification` (typeId 811) + `EventNotificationList` (916) + `StatusChangeNotification` (821) — strong-typed `fromExtension` / `toExtensionObject` |
| Security policy | `None` (full); `Basic128Rsa15` / `Basic256` / `Basic256Sha256` / `Aes128/256_Sha256_RsaOaep/Pss` layer on top of the framing (body wrapping hook) |
| User identity token | Anonymous (full); UserName / X.509 cert (extension point) |

## Quick start (paired in-memory transport — runs on the VM and on
the web)

```dart
import 'package:mcp_io_opcua/mcp_io_opcua.dart';

final transport = InMemoryOpcUaByteTransport();
// Pair with a fake server transport in tests, or connect to the
// production TCP transport (see below).

final session = OpcUaProtocolSession(
  transport: transport,
  endpoint: Uri.parse('opc.tcp://localhost:4840'),
  clientDescription: const OpcUaApplicationDescription(
    applicationUri: 'urn:my-app',
    productUri: 'urn:my-app:product',
    applicationName: OpcUaLocalizedText(text: 'My App'),
  ),
);
await session.open();
await session.hello();
await session.openSecureChannel();
await session.createSession(sessionName: 'demo');
await session.activateSession();
```

## Production TCP

Import the io-only entry point on VM / Flutter desktop / Flutter
mobile (web builds stick to the web-safe main library):

```dart
import 'package:mcp_io_opcua/mcp_io_opcua.dart';
import 'package:mcp_io_opcua/io.dart';

final transport = TcpOpcUaByteTransport.fromEndpoint(
  Uri.parse('opc.tcp://10.0.0.50:4840'),
);
final session = OpcUaProtocolSession(transport: transport, ...);
```

## Subscription publish loop

`OpcUaPublishLoop` keeps `maxInFlight` PublishRequests pending,
accumulates per-subscription acknowledgements, and fans
`NotificationMessage`s out to per-subscription broadcast streams:

```dart
final subResp = await session.createSubscription(
  OpcUaCreateSubscriptionRequest(
    header: ..., requestedPublishingInterval: 250,
  ),
);

final loop = OpcUaPublishLoop(session: session);
loop.register(subResp.subscriptionId).listen((notif) {
  for (final eo in notif.notificationData) {
    final dcn = OpcUaDataChangeNotification.fromExtension(eo);
    for (final mi in dcn.monitoredItems) {
      // mi.clientHandle, mi.value.value, mi.value.sourceTimestamp ...
    }
  }
});
await loop.start();

await session.createMonitoredItems(...);
```

## License

MIT — see [LICENSE](LICENSE).
