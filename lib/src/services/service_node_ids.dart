/// Numeric BinaryEncoding NodeIds for OPC UA service requests / responses
/// (Part 4 §A.2 Object Identifiers, OPC UA NodeSet `Opc.Ua.NodeIds.csv`).
///
/// Each integer is an `i=` identifier in namespace 0. Senders include this
/// NodeId as the first field of the SecureChannel body (the message type
/// identifier) followed by the encoded request / response struct.
library;

/// `ReadRequest` BinaryEncoding NodeId.
const int kOpcUaNodeIdReadRequest = 631;

/// `ReadResponse` BinaryEncoding NodeId.
const int kOpcUaNodeIdReadResponse = 634;

/// `WriteRequest` BinaryEncoding NodeId.
const int kOpcUaNodeIdWriteRequest = 673;

/// `WriteResponse` BinaryEncoding NodeId.
const int kOpcUaNodeIdWriteResponse = 676;

/// `BrowseRequest` BinaryEncoding NodeId.
const int kOpcUaNodeIdBrowseRequest = 527;

/// `BrowseResponse` BinaryEncoding NodeId.
const int kOpcUaNodeIdBrowseResponse = 530;

/// `CallRequest` BinaryEncoding NodeId.
const int kOpcUaNodeIdCallRequest = 712;

/// `CallResponse` BinaryEncoding NodeId.
const int kOpcUaNodeIdCallResponse = 715;

/// `HistoryReadRequest` BinaryEncoding NodeId.
const int kOpcUaNodeIdHistoryReadRequest = 664;

/// `HistoryReadResponse` BinaryEncoding NodeId.
const int kOpcUaNodeIdHistoryReadResponse = 667;

/// SecureChannel service set BinaryEncoding NodeIds (Part 4 §5.5).
const int kOpcUaNodeIdOpenSecureChannelRequest = 446;
const int kOpcUaNodeIdOpenSecureChannelResponse = 449;
const int kOpcUaNodeIdCloseSecureChannelRequest = 452;
const int kOpcUaNodeIdCloseSecureChannelResponse = 455;

/// Session service set BinaryEncoding NodeIds (Part 4 §5.6).
const int kOpcUaNodeIdCreateSessionRequest = 461;
const int kOpcUaNodeIdCreateSessionResponse = 464;
const int kOpcUaNodeIdActivateSessionRequest = 467;
const int kOpcUaNodeIdActivateSessionResponse = 470;
const int kOpcUaNodeIdCloseSessionRequest = 473;
const int kOpcUaNodeIdCloseSessionResponse = 476;

/// Anonymous user identity token BinaryEncoding NodeId.
const int kOpcUaNodeIdAnonymousIdentityToken = 321;

/// UserName user identity token BinaryEncoding NodeId.
const int kOpcUaNodeIdUserNameIdentityToken = 324;

/// Subscription service set BinaryEncoding NodeIds (Part 4 §5.13).
const int kOpcUaNodeIdCreateSubscriptionRequest = 787;
const int kOpcUaNodeIdCreateSubscriptionResponse = 790;
const int kOpcUaNodeIdModifySubscriptionRequest = 793;
const int kOpcUaNodeIdModifySubscriptionResponse = 796;
const int kOpcUaNodeIdDeleteSubscriptionsRequest = 847;
const int kOpcUaNodeIdDeleteSubscriptionsResponse = 850;
const int kOpcUaNodeIdSetPublishingModeRequest = 799;
const int kOpcUaNodeIdSetPublishingModeResponse = 802;
const int kOpcUaNodeIdPublishRequest = 826;
const int kOpcUaNodeIdPublishResponse = 829;
const int kOpcUaNodeIdRepublishRequest = 832;
const int kOpcUaNodeIdRepublishResponse = 835;

/// Notification body BinaryEncoding NodeIds (Part 4 §7.16).
const int kOpcUaNodeIdDataChangeNotification = 811;
const int kOpcUaNodeIdMonitoredItemNotification = 808;
const int kOpcUaNodeIdEventNotificationList = 916;
const int kOpcUaNodeIdEventFieldList = 919;
const int kOpcUaNodeIdStatusChangeNotification = 821;

/// MonitoredItems service set BinaryEncoding NodeIds (Part 4 §5.12).
const int kOpcUaNodeIdCreateMonitoredItemsRequest = 751;
const int kOpcUaNodeIdCreateMonitoredItemsResponse = 754;
const int kOpcUaNodeIdModifyMonitoredItemsRequest = 763;
const int kOpcUaNodeIdModifyMonitoredItemsResponse = 766;
const int kOpcUaNodeIdDeleteMonitoredItemsRequest = 783;
const int kOpcUaNodeIdDeleteMonitoredItemsResponse = 786;
const int kOpcUaNodeIdSetMonitoringModeRequest = 769;
const int kOpcUaNodeIdSetMonitoringModeResponse = 772;

/// Standard OPC UA Attribute identifiers (Part 6 §A.1 Attributes).
class OpcUaAttribute {
  static const int nodeId = 1;
  static const int nodeClass = 2;
  static const int browseName = 3;
  static const int displayName = 4;
  static const int description = 5;
  static const int writeMask = 6;
  static const int userWriteMask = 7;
  static const int isAbstract = 8;
  static const int symmetric = 9;
  static const int inverseName = 10;
  static const int containsNoLoops = 11;
  static const int eventNotifier = 12;

  /// `Value` — the attribute carrying the live data point. This is the one
  /// touched by Read / Write of process variables.
  static const int value = 13;
  static const int dataType = 14;
  static const int valueRank = 15;
  static const int arrayDimensions = 16;
  static const int accessLevel = 17;
  static const int userAccessLevel = 18;
  static const int minimumSamplingInterval = 19;
  static const int historizing = 20;
  static const int executable = 21;
  static const int userExecutable = 22;
}
