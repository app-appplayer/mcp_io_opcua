/// Protocol-level OPC UA session orchestration.
///
/// `OpcUaProtocolSession` glues together the lower-level pieces — byte
/// transport, frame pump, secure channel framing, service codecs — into
/// a coherent client-side state machine:
///
/// 1. [hello] — sends `HEL`, awaits `ACK`.
/// 2. [openSecureChannel] — sends `OPN(OpenSecureChannelRequest)`, captures
///    `channelId` + `tokenId` from the response.
/// 3. [createSession] — sends `MSG(CreateSessionRequest)`, captures
///    `authenticationToken`.
/// 4. [activateSession] — sends `MSG(ActivateSessionRequest)`.
/// 5. Service calls — `MSG(<Service>Request)` → `MSG(<Service>Response)`,
///    matched by sequence header `requestId`.
/// 6. [closeSession] + [closeSecureChannel] + transport close.
///
/// Sequence numbers and request ids are monotonic uint32 counters
/// allocated lazily (1, 2, 3, ...). The pending-request map is keyed
/// by request id; the protocol session does not implement chunked
/// service responses (every MSG is `chunkType='F'`).
///
/// Security policy is fixed to `None` in this iteration; sign /
/// signAndEncrypt would layer a `SecurityProvider` between body bytes
/// and `_transport.send`.
library;

import 'dart:async';
import 'dart:typed_data';

import '../encoding/binary_reader.dart';
import '../encoding/binary_writer.dart';
import '../encoding/extension_object_codec.dart';
import '../encoding/node_id_codec.dart';
import '../opcua_hello.dart';
import '../opcua_types.dart';
import '../secure_channel/secure_channel.dart';
import '../secure_channel/security_policy.dart';
import '../services/browse_service.dart';
import '../services/call_service.dart';
import '../services/history_read_service.dart';
import '../services/monitored_items_service.dart';
import '../services/read_service.dart';
import '../services/request_header.dart';
import '../services/secure_channel_service.dart';
import '../services/service_node_ids.dart';
import '../services/session_descriptors.dart';
import '../services/session_service.dart';
import '../services/subscription_service.dart';
import '../services/write_service.dart';
import 'byte_transport.dart';
import 'frame_pump.dart';

class OpcUaProtocolSession {
  final OpcUaByteTransport _transport;
  final Uri endpoint;
  final OpcUaApplicationDescription clientDescription;

  /// Default request timeout for any wait-for-frame operation.
  final Duration defaultTimeout;

  /// SecureChannel security policy. Defaults to [NoneSecurityPolicy]
  /// (pass-through). Hosts that need Sign / SignAndEncrypt provide
  /// a [CryptoSecurityPolicy] subclass — see
  /// `secure_channel/security_policy.dart`.
  final OpcUaSecurityPolicy securityPolicy;

  final OpcUaFramePump _pump = OpcUaFramePump();

  StreamSubscription<Uint8List>? _byteSub;
  StreamSubscription<OpcUaWireFrame>? _frameSub;

  // Wire counters.
  int _channelId = 0;
  int _tokenId = 0;
  int _seqNum = 0;
  int _reqId = 0;
  int _reqHandle = 0;

  // Session state populated by createSession / activateSession.
  OpcUaNodeIdValue _authToken =
      const OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: 0);
  OpcUaNodeIdValue? _sessionId;

  // Routing.
  final Map<int, Completer<Uint8List>> _pendingByReqId = {};
  Completer<OpcUaWireFrame>? _expectingTransportFrame;
  String? _expectingType;

  bool _opened = false;
  bool _closed = false;

  OpcUaProtocolSession({
    required OpcUaByteTransport transport,
    required this.endpoint,
    required this.clientDescription,
    this.defaultTimeout = const Duration(seconds: 5),
    this.securityPolicy = const NoneSecurityPolicy(),
  }) : _transport = transport;

  // === Public state accessors ===

  int get secureChannelId => _channelId;
  int get tokenId => _tokenId;
  OpcUaNodeIdValue get authenticationToken => _authToken;
  OpcUaNodeIdValue? get sessionId => _sessionId;

  // === Lifecycle ===

  /// Opens the byte transport and starts the frame pump. Idempotent.
  Future<void> open() async {
    if (_opened) return;
    if (_closed) {
      throw StateError('OpcUaProtocolSession already closed');
    }
    await _transport.open();
    _byteSub = _transport.incoming.listen(
      _pump.feed,
      onError: (Object e, StackTrace st) => _failAllPending(e, st),
    );
    _frameSub = _pump.frames.listen(
      _onFrame,
      onError: (Object e, StackTrace st) => _failAllPending(e, st),
    );
    _opened = true;
  }

  /// Closes the transport (does not send CLO — call [closeSecureChannel]
  /// separately if a polite shutdown is desired).
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _frameSub?.cancel();
    await _byteSub?.cancel();
    await _pump.close();
    await _transport.close();
    _failAllPending(StateError('session closed'), StackTrace.current);
  }

  // === 1. HEL / ACK ===

  Future<OpcUaAcknowledgeMessage> hello({
    int receiveBufferSize = 65535,
    int sendBufferSize = 65535,
    int maxMessageSize = 16777216,
    int maxChunkCount = 0,
  }) async {
    _ensureOpen();
    final hel = OpcUaHelloMessage(
      receiveBufferSize: receiveBufferSize,
      sendBufferSize: sendBufferSize,
      maxMessageSize: maxMessageSize,
      maxChunkCount: maxChunkCount,
      endpointUrl: endpoint.toString(),
    ).encode();
    final waiter = _expectTransportFrame('ACK');
    await _transport.send(hel);
    final ack = await waiter.future.timeout(defaultTimeout);
    return OpcUaAcknowledgeMessage.decode(ack.bytes);
  }

  // === 2. OPN ===

  Future<OpcUaOpenSecureChannelResponse> openSecureChannel({
    Duration requestedLifetime = const Duration(hours: 1),
  }) async {
    _ensureOpen();
    final reqId = _nextRequestId();
    final seq = _nextSequenceNumber();
    final waiter = _registerPending(reqId);

    final body = BinaryWriter();
    NodeIdCodec.encode(
      body,
      const OpcUaNodeIdNumeric(
        namespaceIndex: 0,
        identifier: kOpcUaNodeIdOpenSecureChannelRequest,
      ),
    );
    OpcUaOpenSecureChannelRequest(
      header: _newRequestHeader(),
      requestedLifetime: requestedLifetime.inMilliseconds,
    ).encode(body);

    final frame = OpcUaSecureChannelFrame.encodeOpn(
      secureChannelId: _channelId,
      asymmetric: OpcUaAsymmetricSecurityHeader(
        securityPolicyUri: securityPolicy.policyUri,
      ),
      sequence: OpcUaSequenceHeader(sequenceNumber: seq, requestId: reqId),
      body: body.takeBytes(),
      policy: securityPolicy,
    );
    await _transport.send(frame);

    final respBody = await waiter.future.timeout(defaultTimeout);
    final reader = BinaryReader(respBody);
    _expectTypeId(reader, kOpcUaNodeIdOpenSecureChannelResponse);
    final resp = OpcUaOpenSecureChannelResponse.decode(reader);
    _channelId = resp.securityToken.channelId;
    _tokenId = resp.securityToken.tokenId;
    return resp;
  }

  // === 3. CreateSession ===

  Future<OpcUaCreateSessionResponse> createSession({
    required String sessionName,
    Duration requestedTimeout = const Duration(minutes: 20),
  }) async {
    final resp = await _callMsgService<OpcUaCreateSessionResponse>(
      requestTypeId: kOpcUaNodeIdCreateSessionRequest,
      responseTypeId: kOpcUaNodeIdCreateSessionResponse,
      encodeBody: (w) => OpcUaCreateSessionRequest(
        header: _newRequestHeader(),
        clientDescription: clientDescription,
        endpointUrl: endpoint.toString(),
        sessionName: sessionName,
        requestedSessionTimeout: requestedTimeout.inMilliseconds.toDouble(),
      ).encode(w),
      decodeResponse: OpcUaCreateSessionResponse.decode,
    );
    _sessionId = resp.sessionId;
    _authToken = resp.authenticationToken;
    return resp;
  }

  // === 4. ActivateSession ===

  Future<OpcUaActivateSessionResponse> activateSession({
    String policyId = 'anonymous',
    List<String> localeIds = const ['en-US'],
  }) async {
    final tokenBody = BinaryWriter();
    OpcUaAnonymousIdentityToken(policyId: policyId).encode(tokenBody);
    final identity = OpcUaExtensionObject(
      typeId: const OpcUaNodeIdNumeric(
        namespaceIndex: 0,
        identifier: kOpcUaNodeIdAnonymousIdentityToken,
      ),
      encoding: ExtensionObjectEncoding.byteString,
      body: Uint8List.fromList(tokenBody.takeBytes()),
    );

    return _callMsgService<OpcUaActivateSessionResponse>(
      requestTypeId: kOpcUaNodeIdActivateSessionRequest,
      responseTypeId: kOpcUaNodeIdActivateSessionResponse,
      encodeBody: (w) => OpcUaActivateSessionRequest(
        header: _newRequestHeader(),
        localeIds: localeIds,
        userIdentityToken: identity,
      ).encode(w),
      decodeResponse: OpcUaActivateSessionResponse.decode,
    );
  }

  // === 5. Service calls ===

  Future<OpcUaReadResponse> read(OpcUaReadRequest request) =>
      _callMsgService<OpcUaReadResponse>(
        requestTypeId: kOpcUaNodeIdReadRequest,
        responseTypeId: kOpcUaNodeIdReadResponse,
        encodeBody: (w) => request.encode(w),
        decodeResponse: OpcUaReadResponse.decode,
      );

  Future<OpcUaWriteResponse> write(OpcUaWriteRequest request) =>
      _callMsgService<OpcUaWriteResponse>(
        requestTypeId: kOpcUaNodeIdWriteRequest,
        responseTypeId: kOpcUaNodeIdWriteResponse,
        encodeBody: (w) => request.encode(w),
        decodeResponse: OpcUaWriteResponse.decode,
      );

  Future<OpcUaBrowseResponse> browse(OpcUaBrowseRequest request) =>
      _callMsgService<OpcUaBrowseResponse>(
        requestTypeId: kOpcUaNodeIdBrowseRequest,
        responseTypeId: kOpcUaNodeIdBrowseResponse,
        encodeBody: (w) => request.encode(w),
        decodeResponse: OpcUaBrowseResponse.decode,
      );

  Future<OpcUaCallResponse> call(OpcUaCallRequest request) =>
      _callMsgService<OpcUaCallResponse>(
        requestTypeId: kOpcUaNodeIdCallRequest,
        responseTypeId: kOpcUaNodeIdCallResponse,
        encodeBody: (w) => request.encode(w),
        decodeResponse: OpcUaCallResponse.decode,
      );

  Future<OpcUaHistoryReadResponse> historyRead(
          OpcUaHistoryReadRequest request) =>
      _callMsgService<OpcUaHistoryReadResponse>(
        requestTypeId: kOpcUaNodeIdHistoryReadRequest,
        responseTypeId: kOpcUaNodeIdHistoryReadResponse,
        encodeBody: (w) => request.encode(w),
        decodeResponse: OpcUaHistoryReadResponse.decode,
      );

  Future<OpcUaCreateSubscriptionResponse> createSubscription(
          OpcUaCreateSubscriptionRequest request) =>
      _callMsgService<OpcUaCreateSubscriptionResponse>(
        requestTypeId: kOpcUaNodeIdCreateSubscriptionRequest,
        responseTypeId: kOpcUaNodeIdCreateSubscriptionResponse,
        encodeBody: (w) => request.encode(w),
        decodeResponse: OpcUaCreateSubscriptionResponse.decode,
      );

  Future<OpcUaPublishResponse> publish(OpcUaPublishRequest request) =>
      _callMsgService<OpcUaPublishResponse>(
        requestTypeId: kOpcUaNodeIdPublishRequest,
        responseTypeId: kOpcUaNodeIdPublishResponse,
        encodeBody: (w) => request.encode(w),
        decodeResponse: OpcUaPublishResponse.decode,
      );

  Future<OpcUaCreateMonitoredItemsResponse> createMonitoredItems(
          OpcUaCreateMonitoredItemsRequest request) =>
      _callMsgService<OpcUaCreateMonitoredItemsResponse>(
        requestTypeId: kOpcUaNodeIdCreateMonitoredItemsRequest,
        responseTypeId: kOpcUaNodeIdCreateMonitoredItemsResponse,
        encodeBody: (w) => request.encode(w),
        decodeResponse: OpcUaCreateMonitoredItemsResponse.decode,
      );

  Future<OpcUaDeleteSubscriptionsResponse> deleteSubscriptions(
          OpcUaDeleteSubscriptionsRequest request) =>
      _callMsgService<OpcUaDeleteSubscriptionsResponse>(
        requestTypeId: kOpcUaNodeIdDeleteSubscriptionsRequest,
        responseTypeId: kOpcUaNodeIdDeleteSubscriptionsResponse,
        encodeBody: (w) => request.encode(w),
        decodeResponse: OpcUaDeleteSubscriptionsResponse.decode,
      );

  // === 6. Close ===

  Future<OpcUaCloseSessionResponse> closeSession({
    bool deleteSubscriptions = true,
  }) =>
      _callMsgService<OpcUaCloseSessionResponse>(
        requestTypeId: kOpcUaNodeIdCloseSessionRequest,
        responseTypeId: kOpcUaNodeIdCloseSessionResponse,
        encodeBody: (w) => OpcUaCloseSessionRequest(
          header: _newRequestHeader(),
          deleteSubscriptions: deleteSubscriptions,
        ).encode(w),
        decodeResponse: OpcUaCloseSessionResponse.decode,
      );

  /// Sends a `CLO` frame and tears down the secure channel. The local
  /// transport is NOT closed by this call — call [close] for that.
  Future<OpcUaCloseSecureChannelResponse> closeSecureChannel() async {
    final reqId = _nextRequestId();
    final seq = _nextSequenceNumber();
    final waiter = _registerPending(reqId);

    final body = BinaryWriter();
    NodeIdCodec.encode(
      body,
      const OpcUaNodeIdNumeric(
        namespaceIndex: 0,
        identifier: kOpcUaNodeIdCloseSecureChannelRequest,
      ),
    );
    OpcUaCloseSecureChannelRequest(header: _newRequestHeader()).encode(body);

    final frame = OpcUaSecureChannelFrame.encodeSymmetric(
      type: OpcUaSecureMessageType.clo,
      secureChannelId: _channelId,
      symmetric: OpcUaSymmetricSecurityHeader(tokenId: _tokenId),
      sequence: OpcUaSequenceHeader(sequenceNumber: seq, requestId: reqId),
      body: body.takeBytes(),
      policy: securityPolicy,
    );
    await _transport.send(frame);

    final respBody = await waiter.future.timeout(defaultTimeout);
    final reader = BinaryReader(respBody);
    _expectTypeId(reader, kOpcUaNodeIdCloseSecureChannelResponse);
    return OpcUaCloseSecureChannelResponse.decode(reader);
  }

  // === Internal ===

  Future<R> _callMsgService<R>({
    required int requestTypeId,
    required int responseTypeId,
    required void Function(BinaryWriter) encodeBody,
    required R Function(BinaryReader) decodeResponse,
  }) async {
    _ensureOpen();
    final reqId = _nextRequestId();
    final seq = _nextSequenceNumber();
    final waiter = _registerPending(reqId);

    final body = BinaryWriter();
    NodeIdCodec.encode(
      body,
      OpcUaNodeIdNumeric(namespaceIndex: 0, identifier: requestTypeId),
    );
    encodeBody(body);

    final frame = OpcUaSecureChannelFrame.encodeSymmetric(
      type: OpcUaSecureMessageType.msg,
      secureChannelId: _channelId,
      symmetric: OpcUaSymmetricSecurityHeader(tokenId: _tokenId),
      sequence: OpcUaSequenceHeader(sequenceNumber: seq, requestId: reqId),
      body: body.takeBytes(),
      policy: securityPolicy,
    );
    await _transport.send(frame);

    final respBody = await waiter.future.timeout(defaultTimeout);
    final reader = BinaryReader(respBody);
    _expectTypeId(reader, responseTypeId);
    return decodeResponse(reader);
  }

  void _onFrame(OpcUaWireFrame frame) {
    final type = frame.messageType;
    if (type == 'ACK' || type == 'HEL' || type == 'ERR') {
      final waiter = _expectingTransportFrame;
      if (waiter != null && _expectingType == type) {
        _expectingTransportFrame = null;
        _expectingType = null;
        if (!waiter.isCompleted) waiter.complete(frame);
      }
      return;
    }
    if (type == 'OPN' || type == 'MSG' || type == 'CLO') {
      OpcUaSecureChannelFrame parsed;
      try {
        parsed =
            OpcUaSecureChannelFrame.decode(frame.bytes, policy: securityPolicy);
      } on Object catch (e, st) {
        _failAllPending(e, st);
        return;
      }
      final reqId = parsed.sequence.requestId;
      final pending = _pendingByReqId.remove(reqId);
      if (pending != null && !pending.isCompleted) {
        pending.complete(Uint8List.fromList(parsed.body));
      }
      // If [type == 'OPN'] also refresh channelId/tokenId from the
      // response payload — we let the caller of [openSecureChannel]
      // do that explicitly so the wire path stays simple here.
    }
  }

  Completer<OpcUaWireFrame> _expectTransportFrame(String type) {
    if (_expectingTransportFrame != null) {
      throw StateError(
        'OpcUaProtocolSession: another transport-frame waiter is in flight',
      );
    }
    final c = Completer<OpcUaWireFrame>();
    _expectingTransportFrame = c;
    _expectingType = type;
    return c;
  }

  Completer<Uint8List> _registerPending(int reqId) {
    final c = Completer<Uint8List>();
    _pendingByReqId[reqId] = c;
    return c;
  }

  void _failAllPending(Object e, StackTrace st) {
    for (final c in _pendingByReqId.values) {
      if (!c.isCompleted) c.completeError(e, st);
    }
    _pendingByReqId.clear();
    final waiter = _expectingTransportFrame;
    if (waiter != null && !waiter.isCompleted) {
      waiter.completeError(e, st);
    }
    _expectingTransportFrame = null;
    _expectingType = null;
  }

  void _ensureOpen() {
    if (!_opened) {
      throw StateError('OpcUaProtocolSession not opened — call open() first');
    }
    if (_closed) {
      throw StateError('OpcUaProtocolSession already closed');
    }
  }

  void _expectTypeId(BinaryReader reader, int expectedNumericId) {
    final id = NodeIdCodec.decode(reader);
    if (id is! OpcUaNodeIdNumeric ||
        id.namespaceIndex != 0 ||
        id.identifier != expectedNumericId) {
      throw OpcUaProtocolError(
        'unexpected response typeId — expected ns=0;i=$expectedNumericId, '
        'got $id',
      );
    }
  }

  int _nextRequestId() => ++_reqId;
  int _nextSequenceNumber() => ++_seqNum;
  int _nextRequestHandle() => ++_reqHandle;

  OpcUaRequestHeader _newRequestHeader() => OpcUaRequestHeader(
        authenticationToken: _authToken,
        timestamp: DateTime.now().toUtc(),
        requestHandle: _nextRequestHandle(),
      );
}
