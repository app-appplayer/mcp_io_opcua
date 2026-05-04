/// Subscription publish/ack loop for [OpcUaProtocolSession].
///
/// OPC UA Subscription model is *server-pushed* — once a subscription
/// is created, the client is expected to keep an outstanding
/// `PublishRequest` for each subscription it cares about so the
/// server has a reply slot to deliver `NotificationMessage`s as they
/// occur. Each successful Publish must be acknowledged in a
/// subsequent PublishRequest by referencing its sequence number.
///
/// `OpcUaPublishLoop` automates the cycle:
///   - keeps [maxInFlight] PublishRequests pending at all times
///   - accumulates per-subscription acknowledgements
///   - decodes the response and routes the `NotificationMessage` to
///     the matching subscription's broadcast stream
///   - re-issues a fresh PublishRequest as soon as one returns
///
/// Higher-level code calls [register]`(subscriptionId)` after a
/// successful `CreateSubscriptionResponse`, listens to the returned
/// stream, and calls [unregister] / [stop] on tear-down.
library;

import 'dart:async';

import '../services/request_header.dart';
import '../services/subscription_service.dart';
import 'protocol_session.dart';

class OpcUaPublishLoop {
  final OpcUaProtocolSession _session;

  /// How many `PublishRequest` calls to keep in flight. The OPC UA
  /// spec recommends ≥ 2 so the server always has a reply slot.
  final int maxInFlight;

  /// When `true`, transient errors restart the request slot after
  /// [errorBackoff]. When `false` an error stops the loop and is
  /// surfaced on every subscription stream.
  final bool restartOnError;

  /// Backoff between restarts when [restartOnError] is `true`.
  final Duration errorBackoff;

  /// Per-subscription dispatch.
  final Map<int, StreamController<OpcUaNotificationMessage>> _streams = {};

  /// Acknowledgements queued for the next PublishRequest.
  final List<OpcUaSubscriptionAcknowledgement> _pendingAcks = [];

  /// Number of in-flight requests.
  int _inFlight = 0;

  bool _running = false;
  bool _disposed = false;

  /// Ack-snapshot used by the most recent in-flight request, kept so
  /// the loop can release them only once the matching response
  /// arrives (mirrors how production OPC UA stacks track outstanding
  /// acks).
  final List<List<OpcUaSubscriptionAcknowledgement>> _inFlightAcks = [];

  OpcUaPublishLoop({
    required OpcUaProtocolSession session,
    this.maxInFlight = 2,
    this.restartOnError = true,
    this.errorBackoff = const Duration(seconds: 1),
  }) : _session = session;

  /// Subscription ids currently routed by this loop.
  Set<int> get subscriptionIds => _streams.keys.toSet();

  /// Returns `true` while [start] has been called and [stop] has not.
  bool get isRunning => _running && !_disposed;

  /// Register a subscription so its `NotificationMessage`s are routed
  /// onto the returned broadcast stream. Re-registering the same id
  /// returns the existing stream.
  Stream<OpcUaNotificationMessage> register(int subscriptionId) {
    final existing = _streams[subscriptionId];
    if (existing != null) return existing.stream;
    final ctrl = StreamController<OpcUaNotificationMessage>.broadcast();
    _streams[subscriptionId] = ctrl;
    return ctrl.stream;
  }

  /// Stop routing notifications for [subscriptionId] and close the
  /// stream returned by [register].
  Future<void> unregister(int subscriptionId) async {
    final ctrl = _streams.remove(subscriptionId);
    if (ctrl != null && !ctrl.isClosed) {
      await ctrl.close();
    }
  }

  /// Begin the loop. Idempotent.
  Future<void> start() async {
    if (_disposed) {
      throw StateError('OpcUaPublishLoop disposed');
    }
    if (_running) return;
    _running = true;
    _topUp();
  }

  /// Stop the loop and close every per-subscription stream.
  Future<void> stop() async {
    if (_disposed) return;
    _disposed = true;
    _running = false;
    for (final ctrl in _streams.values) {
      if (!ctrl.isClosed) await ctrl.close();
    }
    _streams.clear();
  }

  // === Internal ===

  void _topUp() {
    if (!isRunning) return;
    while (_inFlight < maxInFlight) {
      _issueOne();
    }
  }

  void _issueOne() {
    _inFlight++;
    final acksForThisRequest = List<OpcUaSubscriptionAcknowledgement>.unmodifiable(
      _pendingAcks,
    );
    _inFlightAcks.add(acksForThisRequest);
    _pendingAcks.clear();
    _session
        .publish(OpcUaPublishRequest(
          header: _newRequestHeader(),
          subscriptionAcknowledgements: acksForThisRequest,
        ))
        .then(_onResponse, onError: _onError);
  }

  void _onResponse(OpcUaPublishResponse response) {
    _inFlight--;
    if (_inFlightAcks.isNotEmpty) _inFlightAcks.removeAt(0);
    if (!isRunning) return;

    // Queue an ack for this notification's sequence number.
    final seq = response.notificationMessage.sequenceNumber;
    if (seq != 0) {
      _pendingAcks.add(OpcUaSubscriptionAcknowledgement(
        subscriptionId: response.subscriptionId, sequenceNumber: seq,
      ));
    }

    final ctrl = _streams[response.subscriptionId];
    if (ctrl != null && !ctrl.isClosed) {
      ctrl.add(response.notificationMessage);
    }
    _topUp();
  }

  void _onError(Object e, StackTrace st) {
    _inFlight--;
    if (_inFlightAcks.isNotEmpty) {
      // Lose the snapshot but re-queue them so they aren't dropped.
      _pendingAcks.insertAll(0, _inFlightAcks.removeAt(0));
    }
    if (_disposed) return;
    if (restartOnError) {
      Timer(errorBackoff, () {
        if (isRunning) _topUp();
      });
      return;
    }
    _running = false;
    for (final ctrl in _streams.values) {
      if (!ctrl.isClosed) ctrl.addError(e, st);
    }
  }

  OpcUaRequestHeader _newRequestHeader() => OpcUaRequestHeader(
        authenticationToken: _session.authenticationToken,
        timestamp: DateTime.now().toUtc(),
        // Use a constant handle — Publish-loop carries no application
        // semantics that depend on the echoed handle.
        requestHandle: 0,
      );
}
