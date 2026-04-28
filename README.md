# MCP IO OPC UA

OPC UA Binary adapter (MVP) for [`mcp_io`](https://pub.dev/packages/mcp_io). Hello/Ack transport codec and `OpcUaSession` abstraction.

```dart
import 'package:mcp_io_opcua/mcp_io_opcua.dart';

final adapter = OpcUaIoAdapter(OpcUaSession(...));
registry.register('opcua-1', adapter);
```

## License

MIT — see [LICENSE](LICENSE).
