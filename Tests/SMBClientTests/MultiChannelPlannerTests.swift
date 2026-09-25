import XCTest
@testable import SMBClient

final class MultiChannelPlannerTests: XCTestCase {
  private typealias Target = MultiChannelPlanner.Target

  private func interface(_ index: UInt32, _ address: String, rss: Bool = false, speed: UInt64 = 1_000_000_000) -> NetworkInterfaceInfo {
    NetworkInterfaceInfo(ifIndex: index, capabilities: rss ? [.rss] : [], linkSpeed: speed, address: address)
  }

  func testSingleNonRSSInterfaceOpensNoExtraConnections() {
    // Windows: ConnectionCountPerNetworkInterface = 1.
    let targets = MultiChannelPlanner.targets(
      interfaces: [interface(1, "192.168.1.10")],
      connectedAddress: "192.168.1.10",
      host: "nas.local",
      port: 445,
      limit: 31
    )
    XCTAssertEqual(targets, [])
  }

  func testRSSInterfaceOpensFourConnections() {
    // Windows: ConnectionCountPerRssNetworkInterface = 4, one already open.
    let targets = MultiChannelPlanner.targets(
      interfaces: [interface(1, "192.168.1.10", rss: true)],
      connectedAddress: "192.168.1.10",
      host: "nas.local",
      port: 445,
      limit: 31
    )
    XCTAssertEqual(targets, Array(repeating: Target(host: "nas.local", port: 445), count: 3))
  }

  func testOtherInterfacesAreUsedByAddress() {
    let targets = MultiChannelPlanner.targets(
      interfaces: [
        interface(1, "192.168.1.10"),
        interface(2, "10.0.0.10", speed: 1_000_000_000),
        interface(3, "10.1.0.10", rss: true, speed: 10_000_000_000),
      ],
      connectedAddress: "192.168.1.10",
      host: "nas.local",
      port: 4450,
      limit: 31
    )
    XCTAssertEqual(
      targets,
      Array(repeating: Target(host: "10.1.0.10", port: 4450), count: 4) + [Target(host: "10.0.0.10", port: 4450)]
    )
  }

  func testUnknownConnectedAddressStaysOnCurrentAddress() {
    // Behind NAT or port forwarding the reported addresses are unreachable.
    let targets = MultiChannelPlanner.targets(
      interfaces: [interface(1, "172.17.0.2", rss: true), interface(2, "172.18.0.2")],
      connectedAddress: "127.0.0.1",
      host: "localhost",
      port: 4445,
      limit: 31
    )
    XCTAssertEqual(targets, Array(repeating: Target(host: "localhost", port: 4445), count: 3))
  }

  func testLimitAndServerMaximum() {
    let interfaces = (1...20).map { interface(UInt32($0), "10.0.\($0).1", rss: true) }
    let limited = MultiChannelPlanner.targets(
      interfaces: interfaces, connectedAddress: "10.0.1.1", host: "server", port: 445, limit: 3
    )
    XCTAssertEqual(limited.count, 3)

    let unlimited = MultiChannelPlanner.targets(
      interfaces: interfaces, connectedAddress: "10.0.1.1", host: "server", port: 445, limit: 1000
    )
    XCTAssertEqual(unlimited.count, 31) // MaximumConnectionCountPerServer = 32

    XCTAssertEqual(MultiChannelPlanner.targets(interfaces: interfaces, connectedAddress: nil, host: "s", port: 445, limit: 0), [])
    XCTAssertEqual(MultiChannelPlanner.targets(interfaces: [], connectedAddress: nil, host: "s", port: 445, limit: 5), [])
  }

  func testOneAddressPerInterfaceInTheConnectedFamily() {
    let targets = MultiChannelPlanner.targets(
      interfaces: [
        interface(1, "192.168.1.10"),
        interface(1, "fd00::10"),
        interface(2, "fd00::20"),
        interface(2, "192.168.2.10"),
        interface(3, "fe80::1"),
        interface(4, "fd00::40"),
      ],
      connectedAddress: "::ffff:192.168.1.10",
      host: "nas",
      port: 445,
      limit: 31
    )
    // Interface 2 by its IPv4 address; link-local and IPv6-only interfaces skipped.
    XCTAssertEqual(targets, [Target(host: "192.168.2.10", port: 445)])
  }

  func testParseInterfaceInfo() {
    func entry(next: UInt32, index: UInt32, capability: UInt32, speed: UInt64, sockaddr: Data) -> Data {
      var data = Data()
      data += next
      data += index
      data += capability
      data += UInt32(0)
      data += speed
      data += sockaddr + Data(count: 128 - sockaddr.count)
      return data
    }
    let ipv4 = Data([0x02, 0x00, 0x01, 0xBD, 192, 168, 1, 10]) + Data(count: 8)
    var ipv6 = Data([0x17, 0x00, 0x00, 0x00, 0, 0, 0, 0])
    ipv6 += Data([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]) + Data(count: 4)

    let buffer = entry(next: 152, index: 3, capability: 1, speed: 10_000_000_000, sockaddr: ipv4)
      + entry(next: 0, index: 3, capability: 0, speed: 1_000_000_000, sockaddr: ipv6)
    let interfaces = NetworkInterfaceInfo.parse(buffer)

    XCTAssertEqual(interfaces.count, 2)
    XCTAssertEqual(interfaces[0].address, "192.168.1.10")
    XCTAssertEqual(interfaces[0].port, 445)
    XCTAssertEqual(interfaces[0].ifIndex, 3)
    XCTAssertTrue(interfaces[0].capabilities.contains(.rss))
    XCTAssertEqual(interfaces[0].linkSpeed, 10_000_000_000)
    XCTAssertEqual(interfaces[1].address, "fd00::10")
    XCTAssertFalse(interfaces[1].capabilities.contains(.rss))
  }

  func testFormatIPv6() {
    XCTAssertEqual(NetworkInterfaceInfo.formatIPv6(Data(count: 16)), "::")
    XCTAssertEqual(NetworkInterfaceInfo.formatIPv6(Data(count: 15) + Data([1])), "::1")
    XCTAssertEqual(
      NetworkInterfaceInfo.formatIPv6(Data([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1])),
      "2001:db8:0:1::1"
    )
    XCTAssertEqual(
      NetworkInterfaceInfo.formatIPv6(Data([0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1])),
      "2001:db8:1:0:1:1:1:1"
    )
  }
}
