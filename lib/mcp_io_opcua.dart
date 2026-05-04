/// OPC UA Binary adapter for mcp_io.
library;

// Legacy MVP types (BC).
export 'src/opcua_types.dart';
export 'src/opcua_hello.dart';
export 'src/opcua_session.dart';
export 'src/opcua_adapter.dart';

// Encoding (Part 6 §5).
export 'src/encoding/binary_reader.dart';
export 'src/encoding/binary_writer.dart';
export 'src/encoding/built_in_types.dart';
export 'src/encoding/data_value_codec.dart';
export 'src/encoding/extension_object_codec.dart';
export 'src/encoding/node_id_codec.dart';
export 'src/encoding/variant_codec.dart';

// SecureChannel framing (Part 6 §7.1.2).
export 'src/secure_channel/secure_channel.dart';
export 'src/secure_channel/security_policy.dart';
export 'src/secure_channel/basic256sha256_policy.dart';
export 'src/secure_channel/aes_sha256_policies.dart';

// Crypto primitives — Sign / Encrypt SecurityPolicy implementations
// layer on top of these.
export 'src/crypto/primitives.dart';
export 'src/crypto/rsa.dart';
export 'src/crypto/key_parsing.dart';

// Session-level byte transport + frame pump + protocol session.
export 'src/session/byte_transport.dart';
export 'src/session/frame_pump.dart';
export 'src/session/protocol_session.dart';
export 'src/session/publish_loop.dart';

// Service set codecs (Part 4).
export 'src/services/service_node_ids.dart';
export 'src/services/request_header.dart';
export 'src/services/read_service.dart';
export 'src/services/write_service.dart';
export 'src/services/browse_service.dart';
export 'src/services/call_service.dart';
export 'src/services/history_read_service.dart';
export 'src/services/subscription_service.dart';
export 'src/services/monitored_items_service.dart';
export 'src/services/notification_data.dart';
export 'src/services/secure_channel_service.dart';
export 'src/services/session_descriptors.dart';
export 'src/services/session_service.dart';
