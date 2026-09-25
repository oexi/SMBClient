import XCTest
@testable import SMBClient

final class SMB3Tests: XCTestCase {
  func testNegotiateEachDialect() async throws {
    let dialects: [Negotiate.Dialects] = [.smb202, .smb210, .smb300, .smb302, .smb311]
    for dialect in dialects {
      let session = Session(host: "localhost", port: 4445)
      try await session.connect()

      let response = try await session.negotiate(dialects: [dialect])
      XCTAssertEqual(response.dialectRevision, dialect.rawValue)
      XCTAssertEqual(session.dialect, dialect)

      session.disconnect()
    }
  }

  func testNegotiateRequestContexts() {
    let request = Negotiate.Request(
      messageId: 0,
      securityMode: [.signingEnabled],
      capabilities: [.encryption],
      dialects: [.smb202, .smb210, .smb300, .smb302, .smb311],
      negotiateContexts: [
        Negotiate.PreauthIntegrityCapabilities(hashAlgorithms: [.sha512], salt: Data(count: 32)).context,
        Negotiate.EncryptionCapabilities(ciphers: [.aes128GCM, .aes128CCM]).context,
        Negotiate.SigningCapabilities(signingAlgorithms: [.aesGMAC, .aesCMAC]).context,
      ]
    )
    let data = request.encoded()
    let reader = ByteReader(data)

    reader.seek(to: 64 + 28)
    let contextOffset: UInt32 = reader.read()
    let contextCount: UInt16 = reader.read()
    XCTAssertEqual(contextOffset, 112)
    XCTAssertEqual(contextCount, 3)

    // Preauth (8 + 38 bytes, padded to 48), encryption (8 + 6, padded to 16),
    // signing (8 + 6, unpadded).
    reader.seek(to: 112)
    XCTAssertEqual(reader.read() as UInt16, Negotiate.NegotiateContextType.preauthIntegrityCapabilities.rawValue)
    reader.seek(to: 112 + 48)
    XCTAssertEqual(reader.read() as UInt16, Negotiate.NegotiateContextType.encryptionCapabilities.rawValue)
    reader.seek(to: 112 + 48 + 16)
    XCTAssertEqual(reader.read() as UInt16, Negotiate.NegotiateContextType.signingCapabilities.rawValue)
    XCTAssertEqual(data.count, 112 + 48 + 16 + 14)
  }

  func testSigningWithEachDialect() async throws {
    let dialects: [Negotiate.Dialects] = [.smb210, .smb300, .smb302, .smb311]
    for dialect in dialects {
      let session = try await login(dialects: [dialect], requireSigning: true)
      XCTAssertEqual(session.dialect, dialect)
      XCTAssertFalse(session.isEncrypted)

      try await session.treeConnect(path: "Alice Share")
      try await roundTrip(session, name: "signed-\(dialect).bin", size: 300_000)
      try await session.treeDisconnect()
      try await session.logoff()
      session.disconnect()
    }
  }

  func testSigningAlgorithms() async throws {
    for algorithm in [Negotiate.SigningAlgorithm.aesGMAC, .aesCMAC] {
      let session = try await login(dialects: [.smb311], requireSigning: true) {
        $0.supportedSigningAlgorithms = [algorithm]
      }
      try await session.treeConnect(path: "Alice Share")
      try await roundTrip(session, name: "signed-\(algorithm).bin", size: 70_000)
      try await session.treeDisconnect()
      try await session.logoff()
      session.disconnect()
    }
  }

  func testEncryptionWithEachDialect() async throws {
    let dialects: [Negotiate.Dialects] = [.smb300, .smb302, .smb311]
    for dialect in dialects {
      let session = try await login(dialects: [dialect], requireEncryption: true)
      XCTAssertTrue(session.isEncrypted)

      try await session.treeConnect(path: "Alice Share")
      let files = try await session.queryDirectory(path: "", pattern: "*")
      XCTAssertFalse(files.isEmpty)
      try await roundTrip(session, name: "encrypted-\(dialect).bin", size: 1_500_000)
      try await session.treeDisconnect()
      try await session.logoff()
      session.disconnect()
    }
  }

  func testEncryptionCiphers() async throws {
    for cipher in [Negotiate.Cipher.aes128GCM, .aes128CCM, .aes256GCM, .aes256CCM] {
      let session = try await login(dialects: [.smb311], requireEncryption: true) {
        $0.supportedCiphers = [cipher]
      }
      XCTAssertTrue(session.isEncrypted)

      try await session.treeConnect(path: "Alice Share")
      try await roundTrip(session, name: "encrypted-\(cipher).bin", size: 200_000)
      try await session.treeDisconnect()
      try await session.logoff()
      session.disconnect()
    }
  }

  func testShareRequiringEncryption() async throws {
    let client = SMBClient(host: "localhost", port: 4445)
    try await client.login(username: "alice", password: "alipass")
    XCTAssertEqual(client.session.dialect, .smb311)
    XCTAssertFalse(client.session.isEncrypted)

    try await client.connectShare("Encrypted")
    XCTAssertTrue(client.session.isEncrypted)

    let files = try await client.listDirectory(path: "")
    XCTAssertFalse(files.isEmpty)

    let data = Data((0..<250_000).map { _ in UInt8.random(in: 0...255) })
    let name = "encrypted-share-\(UUID().uuidString).bin"
    try await client.upload(content: data, path: name)
    let downloaded = try await client.download(path: name)
    XCTAssertEqual(downloaded, data)
    try await client.deleteFile(path: name)

    try await client.disconnectShare()
    try await client.logoff()
  }

  func testShareRequiringEncryptionFailsWithSMB2() async throws {
    let session = try await login(dialects: [.smb210])
    do {
      try await session.treeConnect(path: "Encrypted")
      _ = try await session.queryDirectory(path: "", pattern: "*")
      XCTFail("An SMB 2.1 session must not be able to use a share that requires encryption")
    } catch {}
    session.disconnect()
  }

  // MARK: - Helpers

  private func login(
    dialects: [Negotiate.Dialects],
    requireSigning: Bool = false,
    requireEncryption: Bool = false,
    configure: (Session) -> Void = { _ in }
  ) async throws -> Session {
    let session = Session(host: "localhost", port: 4445)
    configure(session)
    try await session.connect()
    try await session.negotiate(
      securityMode: [requireSigning ? .signingRequired : .signingEnabled],
      dialects: dialects
    )
    try await session.sessionSetup(
      username: "alice",
      password: "alipass",
      requireSigning: requireSigning,
      requireEncryption: requireEncryption
    )
    return session
  }

  private func roundTrip(_ session: Session, name: String, size: Int) async throws {
    let data = Data((0..<size).map { _ in UInt8.random(in: 0...255) })

    let writer = FileWriter(session: session, path: name)
    try await writer.upload(data: data, progressHandler: { _ in })
    try await writer.close()

    let reader = FileReader(session: session, path: name)
    let downloaded = try await reader.download(progressHandler: { _ in })
    try await reader.close()
    XCTAssertEqual(downloaded, data, name)

    try await session.deleteFile(path: name)
  }
}
