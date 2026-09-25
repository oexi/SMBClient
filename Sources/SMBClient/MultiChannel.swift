import Foundation

/// One entry of FSCTL_QUERY_NETWORK_INTERFACE_INFO (MS-SMB2 2.2.32.5).
public struct NetworkInterfaceInfo: Equatable, Sendable {
  public let ifIndex: UInt32
  public let capabilities: Capabilities
  /// Link speed in bits per second.
  public let linkSpeed: UInt64
  /// Numeric IPv4 or IPv6 address.
  public let address: String
  public let port: UInt16

  public init(ifIndex: UInt32, capabilities: Capabilities, linkSpeed: UInt64, address: String, port: UInt16 = 0) {
    self.ifIndex = ifIndex
    self.capabilities = capabilities
    self.linkSpeed = linkSpeed
    self.address = address
    self.port = port
  }

  public struct Capabilities: OptionSet, Sendable {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
      self.rawValue = rawValue
    }

    public static let rss = Capabilities(rawValue: 0x00000001)
    public static let rdma = Capabilities(rawValue: 0x00000002)
  }

  public var isIPv6: Bool {
    address.contains(":")
  }

  /// Parses the output buffer of FSCTL_QUERY_NETWORK_INTERFACE_INFO.
  static func parse(_ data: Data) -> [NetworkInterfaceInfo] {
    let data = Data(data)
    let entrySize = 24 + 128
    var interfaces = [NetworkInterfaceInfo]()
    var offset = 0

    while offset + entrySize <= data.count {
      let reader = ByteReader(data)
      reader.seek(to: offset)
      let next: UInt32 = reader.read()
      let ifIndex: UInt32 = reader.read()
      let capabilities: UInt32 = reader.read()
      let _: UInt32 = reader.read()
      let linkSpeed: UInt64 = reader.read()

      let family: UInt16 = reader.read()
      let portBytes = reader.read(count: 2)
      let port = UInt16(portBytes[0]) << 8 | UInt16(portBytes[1])

      var address: String?
      switch family {
      case 0x0002: // InterNetwork
        address = reader.read(count: 4).map { String($0) }.joined(separator: ".")
      case 0x0017: // InterNetworkV6
        let _: UInt32 = reader.read() // FlowInfo
        address = formatIPv6(reader.read(count: 16))
      default:
        break
      }

      if let address {
        interfaces.append(NetworkInterfaceInfo(
          ifIndex: ifIndex,
          capabilities: Capabilities(rawValue: capabilities),
          linkSpeed: linkSpeed,
          address: address,
          port: port
        ))
      }

      guard next > 0 else { break }
      offset += Int(next)
    }

    return interfaces
  }

  /// Formats an IPv6 address per RFC 5952 (lowercase, longest zero run
  /// compressed).
  static func formatIPv6(_ bytes: Data) -> String {
    let bytes = [UInt8](bytes)
    let groups = (0..<8).map { UInt16(bytes[$0 * 2]) << 8 | UInt16(bytes[$0 * 2 + 1]) }

    var bestStart = -1
    var bestLength = 0
    var index = 0
    while index < 8 {
      guard groups[index] == 0 else {
        index += 1
        continue
      }
      let start = index
      while index < 8 && groups[index] == 0 {
        index += 1
      }
      if index - start > bestLength {
        bestStart = start
        bestLength = index - start
      }
    }

    let hex = groups.map { String($0, radix: 16) }
    guard bestLength >= 2 else {
      return hex.joined(separator: ":")
    }
    let head = hex[..<bestStart].joined(separator: ":")
    let tail = hex[(bestStart + bestLength)...].joined(separator: ":")
    return head + "::" + tail
  }
}

/// Decides which extra connections to open for multichannel, following the
/// Windows SMB client defaults: 4 connections per RSS-capable interface
/// (ConnectionCountPerRssNetworkInterface), 1 per other interface
/// (ConnectionCountPerNetworkInterface), and at most 32 per server
/// (MaximumConnectionCountPerServer).
enum MultiChannelPlanner {
  static let connectionsPerRSSInterface = 4
  static let connectionsPerInterface = 1
  static let maximumConnectionsPerServer = 32

  struct Target: Equatable {
    let host: String
    let port: Int
  }

  static func connectionCount(for interface: NetworkInterfaceInfo) -> Int {
    interface.capabilities.contains(.rss) ? connectionsPerRSSInterface : connectionsPerInterface
  }

  /// Returns the extra connections to open, in order of preference, besides
  /// the one already connected to `host`:`port`.
  ///
  /// - `connectedAddress`: the numeric address the current connection
  ///   reached. When it is not one of the server's interfaces (NAT, port
  ///   forwarding), the server's other addresses are probably unreachable,
  ///   so extra connections go to the address already in use, as many as
  ///   the server's best interface allows.
  /// - `limit`: how many extra connections may be opened.
  static func targets(
    interfaces: [NetworkInterfaceInfo],
    connectedAddress: String?,
    host: String,
    port: Int,
    limit: Int
  ) -> [Target] {
    guard limit > 0, !interfaces.isEmpty else {
      return []
    }

    let connected = connectedAddress.map(normalize)
    let connectedIsIPv6 = connected?.contains(":") ?? false
    let primary = interfaces.first { normalize($0.address) == connected }

    // One address per interface, preferring the family in use.
    var byIndex = [UInt32: NetworkInterfaceInfo]()
    var order = [UInt32]()
    for interface in interfaces where !isLinkLocal(interface.address) {
      if let existing = byIndex[interface.ifIndex] {
        if existing.isIPv6 != connectedIsIPv6 && interface.isIPv6 == connectedIsIPv6 {
          byIndex[interface.ifIndex] = interface
        }
      } else {
        byIndex[interface.ifIndex] = interface
        order.append(interface.ifIndex)
      }
    }

    let current = Target(host: host, port: port)
    var targets = [Target]()

    if let primary {
      targets += Array(repeating: current, count: connectionCount(for: primary) - 1)

      let others = order
        .compactMap { byIndex[$0] }
        .filter { $0.ifIndex != primary.ifIndex && $0.isIPv6 == connectedIsIPv6 }
        .sorted {
          let lhsRSS = $0.capabilities.contains(.rss)
          let rhsRSS = $1.capabilities.contains(.rss)
          if lhsRSS != rhsRSS { return lhsRSS }
          return $0.linkSpeed > $1.linkSpeed
        }
      for interface in others {
        let target = Target(host: interface.address, port: port)
        targets += Array(repeating: target, count: connectionCount(for: interface))
      }
    } else {
      let best = interfaces.map(connectionCount(for:)).max() ?? connectionsPerInterface
      targets += Array(repeating: current, count: best - 1)
    }

    return Array(targets.prefix(min(limit, maximumConnectionsPerServer - 1)))
  }

  static func normalize(_ address: String) -> String {
    var address = address.lowercased()
    if let scope = address.firstIndex(of: "%") {
      address = String(address[..<scope])
    }
    if address.hasPrefix("::ffff:"), address.contains(".") {
      address = String(address.dropFirst(7))
    }
    return address
  }

  private static func isLinkLocal(_ address: String) -> Bool {
    let address = normalize(address)
    return address.hasPrefix("fe80:") || address.hasPrefix("169.254.")
  }
}
