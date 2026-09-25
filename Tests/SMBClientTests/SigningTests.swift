import XCTest
@testable import SMBClient

final class SigningTests: XCTestCase {
  private let cases: [(Negotiate.Dialects, Negotiate.SigningAlgorithm)] = [
    (.smb210, .hmacSHA256),
    (.smb302, .aesCMAC),
    (.smb311, .aesCMAC),
    (.smb311, .aesGMAC),
  ]

  /// A response-shaped message: SERVER_TO_REDIR set, with a payload.
  private func response() -> Data {
    let header = Header(command: .read, flags: [.serverToRedir], messageId: 42, treeId: 1, sessionId: 7)
    return header.encoded() + Data((0..<200).map { UInt8(truncatingIfNeeded: $0) })
  }

  func testVerifyAcceptsValidSignature() throws {
    for (dialect, algorithm) in cases {
      let session = Session(host: "localhost")
      session.configureSigning(dialect: dialect, algorithm: algorithm, key: Crypto.randomBytes(count: 16), required: true)

      let signed = try session.sign(response(), force: true)
      XCTAssertTrue(Header(data: signed).flags.contains(.signed))
      XCTAssertNoThrow(try session.verify(signed, encrypted: false, policy: .required), "\(dialect) \(algorithm)")
    }
  }

  func testVerifyRejectsTamperedMessage() throws {
    for (dialect, algorithm) in cases {
      let session = Session(host: "localhost")
      session.configureSigning(dialect: dialect, algorithm: algorithm, key: Crypto.randomBytes(count: 16), required: true)

      var tampered = try session.sign(response(), force: true)
      tampered[100] ^= 0x01
      XCTAssertThrowsError(try session.verify(tampered, encrypted: false, policy: .standard)) {
        XCTAssertEqual($0 as? SecurityError, .signatureMismatch)
      }
    }
  }

  func testVerifyRejectsWrongKey() throws {
    let signer = Session(host: "localhost")
    signer.configureSigning(dialect: .smb311, algorithm: .aesGMAC, key: Crypto.randomBytes(count: 16), required: true)
    let verifier = Session(host: "localhost")
    verifier.configureSigning(dialect: .smb311, algorithm: .aesGMAC, key: Crypto.randomBytes(count: 16), required: true)

    let signed = try signer.sign(response(), force: true)
    XCTAssertThrowsError(try verifier.verify(signed, encrypted: false, policy: .standard))
  }

  func testUnsignedResponses() throws {
    let session = Session(host: "localhost")
    session.configureSigning(dialect: .smb311, algorithm: .aesCMAC, key: Crypto.randomBytes(count: 16), required: true)

    let unsigned = response()
    XCTAssertThrowsError(try session.verify(unsigned, encrypted: false, policy: .standard)) {
      XCTAssertEqual($0 as? SecurityError, .unsignedResponse)
    }
    XCTAssertThrowsError(try session.verify(unsigned, encrypted: false, policy: .required))
    XCTAssertNoThrow(try session.verify(unsigned, encrypted: false, policy: .ifSigned))
    // Encrypted responses are authenticated by the cipher.
    XCTAssertNoThrow(try session.verify(unsigned, encrypted: true, policy: .required))

    // Unsigned error responses are tolerated unless a signature is required.
    var error = unsigned
    error.replaceSubrange(8..<12, with: [0x22, 0x00, 0x00, 0xC0]) // STATUS_ACCESS_DENIED
    XCTAssertNoThrow(try session.verify(error, encrypted: false, policy: .standard))
    XCTAssertThrowsError(try session.verify(error, encrypted: false, policy: .required))
  }

  func testSplitCompoundResponse() {
    var first = Header(command: .create, messageId: 1, sessionId: 1).encoded() + Data(count: 20)
    let second = Header(command: .close, messageId: 2, sessionId: 1).encoded() + Data(count: 5)
    first.replaceSubrange(20..<24, with: [88, 0, 0, 0]) // NextCommand: 84 bytes + 4 padding
    let frame = first + Data(count: 4) + second

    let messages = Connection.split(frame)
    XCTAssertEqual(messages.count, 2)
    XCTAssertEqual(messages[0].count, 88)
    XCTAssertEqual(messages[1], second)
  }
}
