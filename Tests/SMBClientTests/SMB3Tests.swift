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

    let data = Crypto.randomBytes(count: 250_000)
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

  func testValidateNegotiate() async throws {
    for dialect in [Negotiate.Dialects.smb300, .smb302] {
      // A successful TREE_CONNECT on 3.0/3.0.2 includes FSCTL_VALIDATE_NEGOTIATE_INFO.
      let session = try await login(dialects: [dialect])
      try await session.treeConnect(path: "Alice Share")
      try await session.treeDisconnect()

      // A NEGOTIATE that was tampered with is detected.
      let info = try XCTUnwrap(session.negotiateInfo)
      session.negotiateInfo = NegotiateInfo(
        clientCapabilities: info.clientCapabilities,
        clientSecurityMode: info.clientSecurityMode,
        dialects: info.dialects,
        serverCapabilities: info.serverCapabilities,
        serverGuid: info.serverGuid,
        serverSecurityMode: info.serverSecurityMode,
        dialectRevision: Negotiate.Dialects.smb202.rawValue
      )
      do {
        try await session.treeConnect(path: "Alice Share")
        XCTFail("Validation should fail for \(dialect)")
      } catch NegotiateError.validationFailed {
      }
      session.disconnect()
    }
  }

  func testCompressionNegotiation() async throws {
    // Samba does not implement SMB2 compression, so this checks that offering
    // the compression context does not break negotiation, and exercises
    // compression if the server does support it.
    let session = try await login(dialects: [.smb311]) {
      $0.supportedCompressionAlgorithms = [.lz77]
    }
    try await session.treeConnect(path: "Scratch")

    let name = "compressible-\(UUID().uuidString).txt"
    let data = Data(String(repeating: "SMB 3.1.1 compression ", count: 50_000).utf8)
    let writer = FileWriter(session: session, path: name)
    try await writer.upload(data: data, progressHandler: { _ in })
    try await writer.close()
    let reader = FileReader(session: session, path: name)
    let downloaded = try await reader.download(progressHandler: { _ in })
    XCTAssertEqual(downloaded, data)
    try await reader.close()
    try await session.deleteFile(path: name)

    try await session.treeDisconnect()
    try await session.logoff()
    session.disconnect()
  }

  func testMultiChannel() async throws {
    for (dialect, requireEncryption) in [(Negotiate.Dialects.smb300, false), (.smb302, true), (.smb311, false), (.smb311, true)] {
      let session = try await login(dialects: [dialect], requireSigning: !requireEncryption, requireEncryption: requireEncryption)
      try await session.treeConnect(path: "Scratch")
      XCTAssertTrue(session.isMultiChannelSupported, "\(dialect)")

      try await session.bindChannel()
      try await session.bindChannel()
      XCTAssertEqual(session.channels.count, 2)
      for channel in session.channels {
        XCTAssertEqual(channel.dialect, dialect)
        XCTAssertEqual(channel.isEncrypted, requireEncryption)
      }

      // 2.5 chunks per channel, so the last round is partial.
      let size = Int(session.maxWriteSize) * 7 + 12_345
      try await roundTrip(session, name: "multichannel-\(dialect)-\(requireEncryption).bin", size: size)

      // Ranged reads across channels.
      let name = "multichannel-range-\(UUID().uuidString).bin"
      let data = Crypto.randomBytes(count: size)
      let writer = FileWriter(session: session, path: name)
      try await writer.upload(data: data, progressHandler: { _ in })
      try await writer.close()
      let reader = FileReader(session: session, path: name)
      let offset = UInt64(session.maxReadSize) / 2
      let range = try await reader.read(offset: offset, length: session.maxReadSize * 3)
      XCTAssertEqual(range, data[Int(offset)..<(Int(offset) + Int(session.maxReadSize) * 3)])
      let tail = try await reader.read(offset: UInt64(size - 100), length: session.maxReadSize * 2)
      XCTAssertEqual(tail, data.suffix(100))
      try await reader.close()
      try await session.deleteFile(path: name)

      try await session.treeDisconnect()
      try await session.logoff()
      session.disconnect()
    }
  }

  func testMultiChannelWithSMBClient() async throws {
    let client = SMBClient(host: "localhost", port: 4445)
    try await client.login(username: "alice", password: "alipass")
    try await client.connectShare("Scratch")
    let channelCount = try await client.enableMultiChannel(channelCount: 3)
    XCTAssertEqual(channelCount, 2)

    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }

    let data = Crypto.randomBytes(count: (Int(client.session.maxWriteSize) * 4 + 999))
    let source = directory.appendingPathComponent("source.bin")
    try data.write(to: source)
    let name = "multichannel-file-\(UUID().uuidString).bin"
    try await client.upload(localPath: source, remotePath: name)

    let destination = directory.appendingPathComponent("destination.bin")
    try await client.download(path: name, localPath: destination)
    XCTAssertEqual(try Data(contentsOf: destination), data)

    try await client.deleteFile(path: name)
    try await client.logoff()
  }

  func testMultiChannelThroughput() async throws {
    // Timing only: the CI server runs under emulation, so no speedup is asserted.
    let size = 64 * 1024 * 1024
    let data = Crypto.randomBytes(count: size)

    for channelCount in [1, 2, 4] {
      let client = SMBClient(host: "localhost", port: 4445)
      try await client.login(username: "alice", password: "alipass")
      try await client.connectShare("Scratch")
      if channelCount > 1 {
        let bound = try await client.enableMultiChannel(channelCount: channelCount)
        XCTAssertEqual(bound, channelCount - 1)
      }

      let name = "throughput-\(channelCount)-\(UUID().uuidString).bin"
      let uploadStart = Date()
      try await client.upload(content: data, path: name)
      let uploadTime = Date().timeIntervalSince(uploadStart)

      let downloadStart = Date()
      let downloaded = try await client.download(path: name)
      let downloadTime = Date().timeIntervalSince(downloadStart)
      XCTAssertEqual(downloaded, data)

      print(String(
        format: "Multichannel throughput: %d channel(s), upload %.1f MB/s, download %.1f MB/s",
        channelCount,
        Double(size) / uploadTime / 1_000_000,
        Double(size) / downloadTime / 1_000_000
      ))

      try await client.deleteFile(path: name)
      try await client.logoff()
    }
  }

  func testMultiChannelNotSupportedOnSMB2() async throws {
    let session = try await login(dialects: [.smb210])
    XCTAssertFalse(session.isMultiChannelSupported)
    do {
      try await session.bindChannel()
      XCTFail("SMB 2.1 cannot bind channels")
    } catch MultiChannelError.notSupported {
    }
    session.disconnect()
  }

  func testQUICTransportConfiguration() {
    let connection = Connection(host: "localhost", port: 443, transport: .quic)
    XCTAssertEqual(connection.port, 443)
    guard case .quic = connection.transport else {
      return XCTFail("Expected QUIC transport")
    }
    let session = Session(host: "localhost", port: 443, transport: .quic)
    XCTAssertEqual(session.server, "localhost")
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
    let data = Crypto.randomBytes(count: size)

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
