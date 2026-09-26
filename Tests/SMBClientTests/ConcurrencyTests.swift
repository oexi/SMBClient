import XCTest
@testable import SMBClient

final class ConcurrencyTests: XCTestCase {
  // MARK: - Message numbering

  func testNumberingFollowsCreditCharge() {
    let session = Session(host: "localhost")
    func request(charge: UInt16) -> Data {
      Header(creditCharge: charge, command: .write, messageId: 0, sessionId: 1).encoded() + Data(count: 16)
    }

    let first = session.numbered(request(charge: 4))
    let second = session.numbered(request(charge: 1))
    // SMB 2.0.2 requests carry no credit charge but still use one ID.
    let third = session.numbered(request(charge: 0))
    let fourth = session.numbered(request(charge: 1))

    XCTAssertEqual(Header(data: first).messageId, 0)
    XCTAssertEqual(Header(data: second).messageId, 4)
    XCTAssertEqual(Header(data: third).messageId, 5)
    XCTAssertEqual(Header(data: fourth).messageId, 6)
    XCTAssertEqual(first.dropFirst(64), Data(count: 16))
  }

  func testCompoundChainsMessagesOnEightByteBoundaries() {
    let create = Header(command: .create, messageId: 0, sessionId: 1).encoded() + Data(repeating: 1, count: 21)
    let close = Header(command: .close, messageId: 0, sessionId: 1).encoded() + Data(repeating: 2, count: 5)

    let packet = Session.compound([create, close])
    let messages = Connection.split(packet)

    XCTAssertEqual(messages.count, 2)
    XCTAssertEqual(Header(data: messages[0]).nextCommand, UInt32(messages[0].count))
    XCTAssertEqual(messages[0].count % 8, 0)
    XCTAssertEqual(Header(data: messages[1]).nextCommand, 0)
    XCTAssertEqual(messages[0].dropFirst(64).prefix(21), Data(repeating: 1, count: 21))
    XCTAssertEqual(messages[1].dropFirst(64).prefix(5), Data(repeating: 2, count: 5))
  }

  // MARK: - Against the test server

  /// Several transfers and a listing at once on one connection. Message IDs
  /// used to be assigned before the connection was held, so these went out
  /// of order and the server dropped the connection.
  func testConcurrentRequestsOnOneConnection() async throws {
    let client = SMBClient(host: "localhost", port: 4445)
    try await client.login(username: "alice", password: "alipass")
    try await client.connectShare("Scratch")

    try await uploadConcurrently(client, prefix: "concurrent")

    try await client.logoff()
  }

  /// The same with multichannel: each channel numbers its own requests, and
  /// concurrent transfers now share every channel.
  func testConcurrentRequestsWithMultiChannel() async throws {
    let client = SMBClient(host: "localhost", port: 4445)
    try await client.login(username: "alice", password: "alipass")
    try await client.connectShare("Scratch")
    let channelCount = try await client.enableMultiChannel(channelCount: 3)
    XCTAssertEqual(channelCount, 2)

    try await uploadConcurrently(client, prefix: "concurrent-multichannel")

    try await client.logoff()
  }

  private func uploadConcurrently(_ client: SMBClient, prefix: String) async throws {
    let chunk = Int(client.session.maxWriteSize)
    let files = [chunk * 3 + 123, chunk + 7, 110].map { size in
      (name: "\(prefix)-\(UUID().uuidString).bin", data: Crypto.randomBytes(count: size))
    }

    async let first: Void = client.upload(content: files[0].data, path: files[0].name)
    async let second: Void = client.upload(content: files[1].data, path: files[1].name)
    async let third: Void = client.upload(content: files[2].data, path: files[2].name)
    async let listing = client.listDirectory(path: "")
    _ = try await (first, second, third, listing)

    let downloaded = try await withThrowingTaskGroup(of: (Int, Data).self) { group in
      for (index, file) in files.enumerated() {
        group.addTask { (index, try await client.download(path: file.name)) }
      }
      var results = [Int: Data]()
      for try await (index, data) in group {
        results[index] = data
      }
      return results
    }
    for (index, file) in files.enumerated() {
      XCTAssertEqual(downloaded[index], file.data, file.name)
    }

    for file in files {
      try await client.deleteFile(path: file.name)
    }
  }
}
