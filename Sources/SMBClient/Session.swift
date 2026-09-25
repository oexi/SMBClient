import Foundation

public class Session {
  private var messageId = SequenceNumber<UInt64>()
  private var sessionId: UInt64 = 0
  private(set) var treeId: UInt32 = 0

  private var isAnonymous = false
  private var signingRequired = false
  private var signingKey: Data?
  private var signingAlgorithm = Negotiate.SigningAlgorithm.hmacSHA256
  private var cipher: Negotiate.Cipher?
  private var preauthIntegrityHashValue = Data(count: 64)
  private var encryptData = false
  private var encryptTree = false
  private var clientGuid = UUID()
  var negotiateInfo: NegotiateInfo?
  private var credentials: Credentials?

  /// Additional channels bound to this session (SMB 3.x multichannel). Large
  /// reads and writes are spread over this session and its channels.
  public private(set) var channels: [Session] = []

  public private(set) var dialect: Negotiate.Dialects?
  /// Ciphers offered for SMB 3.1.1, in order of preference.
  public var supportedCiphers: [Negotiate.Cipher] = [.aes128GCM, .aes128CCM, .aes256GCM, .aes256CCM]
  /// Signing algorithms offered for SMB 3.1.1, in order of preference.
  public var supportedSigningAlgorithms: [Negotiate.SigningAlgorithm] = [.aesGMAC, .aesCMAC]
  /// Compression algorithms offered for SMB 3.1.1. Empty (the default) turns
  /// compression off. Only `.lz77` is implemented.
  public var supportedCompressionAlgorithms: [Negotiate.CompressionAlgorithm] = []
  /// Whether SMB 3.1.1 compression was negotiated on this connection.
  public var isCompressionEnabled: Bool {
    connection.messageCompressor != nil
  }
  /// Whether messages on this session and tree are encrypted (SMB 3.x).
  public var isEncrypted: Bool {
    connection.messageCipher != nil && (encryptData || encryptTree)
  }

  public private(set) var maxTransactSize: UInt32 = 0
  public private(set) var maxReadSize: UInt32 = 0
  public private(set) var maxWriteSize: UInt32 = 0

  public var server: String { connection.host }
  public private(set) var connectedTree: String?

  public var onDisconnected: (Error) -> Void {
    didSet {
      connection.onDisconnected = onDisconnected
    }
  }

  private let connection: Connection

  public convenience init(host: String) {
    self.init(Connection(host: host))
  }

  public convenience init(host: String, port: Int) {
    self.init(Connection(host: host, port: port))
  }

  /// Creates a session over the given transport, for example SMB over QUIC
  /// (`.quic`, usually on port 443).
  public convenience init(host: String, port: Int, transport: Connection.Transport) {
    self.init(Connection(host: host, port: port, transport: transport))
  }

  private init(_ connection: Connection) {
    self.connection = connection
    onDisconnected = { _ in }
  }

  func newSession() -> Session {
    let session = Session(connection)

    session.messageId = messageId
    session.sessionId = sessionId
    session.treeId = 0

    session.isAnonymous = isAnonymous
    session.signingRequired = signingRequired
    session.signingKey = signingKey
    session.signingAlgorithm = signingAlgorithm
    session.cipher = cipher
    session.encryptData = encryptData
    session.dialect = dialect
    session.clientGuid = clientGuid
    session.negotiateInfo = negotiateInfo
    session.credentials = credentials
    session.channels = channels

    session.maxTransactSize = maxTransactSize
    session.maxReadSize = maxReadSize
    session.maxWriteSize = maxWriteSize

    return session
  }

  func treeAccessor(share: String) -> TreeAccessor {
    TreeAccessor(session: self, share: share)
  }

  public func connect() async throws {
    try await connection.connect()
  }

  public func disconnect() {
    for channel in channels {
      channel.disconnect()
    }
    connection.disconnect()
  }

  @discardableResult
  public func negotiate(
    securityMode: Negotiate.SecurityMode = [.signingEnabled],
    dialects: [Negotiate.Dialects] = [.smb202, .smb210, .smb300, .smb302, .smb311]
  ) async throws -> Negotiate.Response {
    var negotiateContexts = [Negotiate.NegotiateContext]()
    if dialects.contains(.smb311) {
      negotiateContexts = [
        Negotiate.PreauthIntegrityCapabilities(hashAlgorithms: [.sha512], salt: Crypto.randomBytes(count: 32)).context,
        Negotiate.EncryptionCapabilities(ciphers: supportedCiphers).context,
        Negotiate.SigningCapabilities(signingAlgorithms: supportedSigningAlgorithms).context,
      ]
      if !supportedCompressionAlgorithms.isEmpty {
        negotiateContexts.append(
          Negotiate.CompressionCapabilities(compressionAlgorithms: supportedCompressionAlgorithms).context
        )
      }
    }
    let supportsSMB3 = dialects.contains { $0.rawValue >= Negotiate.Dialects.smb300.rawValue }

    let request = Negotiate.Request(
      messageId: messageId.next(),
      securityMode: securityMode,
      capabilities: supportsSMB3 ? [.encryption, .multiChannel] : [],
      clientGuid: clientGuid,
      dialects: dialects,
      negotiateContexts: negotiateContexts
    )

    let requestData = request.encoded()
    let responseData = try await connection.send(requestData)
    let response = Negotiate.Response(data: responseData)

    dialect = Negotiate.Dialects(rawValue: response.dialectRevision)
    switch dialect {
    case .smb311:
      guard response.preauthIntegrityCapabilities?.hashAlgorithms.contains(.sha512) == true else {
        throw NegotiateError.missingPreauthIntegrity
      }
      preauthIntegrityHashValue = Crypto.sha512(Data(count: 64) + requestData)
      preauthIntegrityHashValue = Crypto.sha512(preauthIntegrityHashValue + responseData)
      signingAlgorithm = response.signingCapabilities?.signingAlgorithms.first ?? .aesCMAC
      cipher = response.encryptionCapabilities?.ciphers.first
      let compressionAlgorithms = (response.compressionCapabilities?.compressionAlgorithms ?? [])
        .filter { supportedCompressionAlgorithms.contains($0) && $0 != .noCompression }
      if !compressionAlgorithms.isEmpty {
        connection.messageCompressor = MessageCompressor(algorithms: compressionAlgorithms)
      }
    case .smb300, .smb302:
      signingAlgorithm = .aesCMAC
      cipher = response.capabilities.contains(.encryption) ? .aes128CCM : nil
    case .smb202, .smb210, .none:
      signingAlgorithm = .hmacSHA256
      cipher = nil
    }

    signingRequired = response.securityMode.contains(.signingRequired) || (securityMode.contains(.signingRequired) && response.securityMode.contains(.signingEnabled))

    negotiateInfo = NegotiateInfo(
      clientCapabilities: request.capabilities,
      clientSecurityMode: request.securityMode,
      dialects: dialects,
      serverCapabilities: response.capabilities,
      serverGuid: response.serverGuid,
      serverSecurityMode: response.securityMode,
      dialectRevision: response.dialectRevision
    )

    maxTransactSize = response.maxTransactSize
    maxReadSize = response.maxReadSize
    maxWriteSize = response.maxWriteSize

    return response
  }

  @discardableResult
  public func sessionSetup(
    username: String?,
    password: String?,
    domain: String? = nil,
    workstation: String? = nil,
    requireSigning: Bool = false,
    requireEncryption: Bool = false
  ) async throws -> SessionSetup.Response {
    var preauthIntegrityHashValue = self.preauthIntegrityHashValue
    func updatePreauthIntegrityHash(_ message: Data) {
      guard dialect == .smb311 else { return }
      preauthIntegrityHashValue = Crypto.sha512(preauthIntegrityHashValue + message)
    }

    let negotiateMessage = NTLM.NegotiateMessage(
      domainName: domain,
      workstationName: workstation
    )
    let securityBuffer = negotiateMessage.encoded()

    let request = SessionSetup.Request(
      messageId: messageId.next(),
      sessionId: 0,
      securityMode: [requireSigning ? .signingRequired : .signingEnabled],
      capabilities: [],
      previousSessionId: 0,
      securityBuffer: securityBuffer
    )
    let requestData = request.encoded()
    updatePreauthIntegrityHash(requestData)
    let responseData = try await connection.send(requestData)
    let response = SessionSetup.Response(data: responseData)

    if NTStatus(response.header.status) == .moreProcessingRequired {
      updatePreauthIntegrityHash(responseData)

      let challengeMessage = NTLM.ChallengeMessage(data: response.buffer)

      let signingKey = Crypto.randomBytes(count: 16)
      let authenticateMessage = challengeMessage.authenticateMessage(
        username: username,
        password: password,
        domain: domain,
        workstation: workstation,
        negotiateMessage: securityBuffer,
        signingKey: signingKey
      )

      let request = SessionSetup.Request(
        messageId: messageId.next(),
        sessionId: response.header.sessionId,
        securityMode: [.signingEnabled],
        capabilities: [],
        previousSessionId: 0,
        securityBuffer: authenticateMessage.encoded()
      )

      let requestData = request.encoded()
      updatePreauthIntegrityHash(requestData)
      let responseData = try await connection.send(requestData)
      let response = SessionSetup.Response(data: responseData)

      sessionId = response.header.sessionId

      isAnonymous = ((username ?? "").isEmpty && (password ?? "").isEmpty)
        || !response.sessionFlags.isDisjoint(with: [.guest, .nullSession])
      credentials = Credentials(username: username, password: password, domain: domain, workstation: workstation)

      try establishKeys(
        sessionKey: signingKey,
        preauthIntegrityHashValue: preauthIntegrityHashValue,
        sessionFlags: response.sessionFlags,
        requireEncryption: requireEncryption
      )

      // The server signs the final SESSION_SETUP response with the new
      // signing key. On SMB 3.1.1 this is what binds the preauth integrity
      // hash, so the signature is mandatory (MS-SMB2 3.2.5.3.1).
      try verify(
        responseData,
        encrypted: false,
        expectEncrypted: false,
        policy: dialect == .smb311 ? .required : .ifSigned
      )

      return response
    } else {
      sessionId = response.header.sessionId
      return response
    }
  }

  private func establishKeys(
    sessionKey: Data,
    preauthIntegrityHashValue: Data,
    sessionFlags: SessionSetup.SessionFlags,
    requireEncryption: Bool
  ) throws {
    var encryptionKey: Data?
    var decryptionKey: Data?

    switch dialect {
    case .smb311:
      signingKey = Crypto.kdf(key: sessionKey, label: Data("SMBSigningKey\0".utf8), context: preauthIntegrityHashValue, length: 16)
      if let cipher {
        encryptionKey = Crypto.kdf(key: sessionKey, label: Data("SMBC2SCipherKey\0".utf8), context: preauthIntegrityHashValue, length: cipher.keyLength)
        decryptionKey = Crypto.kdf(key: sessionKey, label: Data("SMBS2CCipherKey\0".utf8), context: preauthIntegrityHashValue, length: cipher.keyLength)
      }
    case .smb300, .smb302:
      signingKey = Crypto.kdf(key: sessionKey, label: Data("SMB2AESCMAC\0".utf8), context: Data("SmbSign\0".utf8), length: 16)
      if cipher != nil {
        encryptionKey = Crypto.kdf(key: sessionKey, label: Data("SMB2AESCCM\0".utf8), context: Data("ServerIn \0".utf8), length: 16)
        decryptionKey = Crypto.kdf(key: sessionKey, label: Data("SMB2AESCCM\0".utf8), context: Data("ServerOut\0".utf8), length: 16)
      }
    case .smb202, .smb210, .none:
      signingKey = sessionKey
    }

    if let cipher, let encryptionKey, let decryptionKey, !isAnonymous {
      connection.messageCipher = MessageCipher(
        cipher: cipher,
        sessionId: sessionId,
        encryptionKey: encryptionKey,
        decryptionKey: decryptionKey
      )
    }

    encryptData = sessionFlags.contains(.encryptData) || requireEncryption
    if encryptData && connection.messageCipher == nil {
      throw MessageCipherError.encryptionNotSupported
    }
  }

  @discardableResult
  public func logoff() async throws -> Logoff.Response {
    let request = Logoff.Request(
      messageId: messageId.next(),
      sessionId: sessionId
    )

    let response = try await send(request)

    sessionId = 0
    for channel in channels {
      channel.disconnect()
    }
    channels = []

    return response
  }

  public func enumShareAll() async throws -> [Share] {
    let treeAccessor = treeAccessor(share: "IPC$")
    let session = try await treeAccessor.session()

    let createResponse = try await session.create(
      desiredAccess: [.readData, .writeData, .appendData, .readAttributes],
      fileAttributes: [.normal],
      shareAccess: [.read, .write],
      createDisposition: .open,
      createOptions: [.nonDirectoryFile],
      name: "srvsvc"
    )

    try await session.bind(fileId: createResponse.fileId)
    let ioCtlResponse = try await session.netShareEnum(fileId: createResponse.fileId)

    let rpcResponse = DCERPC.Response(data: ioCtlResponse.buffer)
    let netShareEnumResponse = NetShareEnumResponse(data: rpcResponse.stub)

    let shares = netShareEnumResponse.shareInfo1.shareInfo

    try await session.close(fileId: createResponse.fileId)

    return shares.compactMap {
      var type = Share.ShareType(rawValue: $0.type & 0x0FFFFFFF)

      if $0.type & Share.ShareType.special.rawValue != 0 {
        type.insert(.special)
      }
      if $0.type & Share.ShareType.temporary.rawValue != 0 {
        type.insert(.temporary)
      }

      return Share(name: $0.name.value, comment: $0.comment.value, type: type)
    }
  }

  @discardableResult
  public func treeConnect(path: String) async throws -> TreeConnect.Response {
    let request = TreeConnect.Request(
      messageId: messageId.next(),
      sessionId: sessionId,
      path: #"\\\#(server)\\#(path)"#
    )

    let response = try await send(request)

    treeId = response.header.treeId
    connectedTree = path

    encryptTree = response.shareFlags.contains(.encryptData)
    if encryptTree && connection.messageCipher == nil {
      throw MessageCipherError.encryptionNotSupported
    }

    if dialect == .smb300 || dialect == .smb302 {
      try await validateNegotiate()
    }

    return response
  }

  @discardableResult
  public func treeDisconnect() async throws -> TreeDisconnect.Response {
    let request = TreeDisconnect.Request(
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId
    )

    let response = try await send(request)

    treeId = 0
    connectedTree = nil
    encryptTree = false

    return response
  }

  public func create(
    desiredAccess: FilePipePrinterAccessMask,
    fileAttributes: FileAttributes,
    shareAccess: Create.ShareAccess,
    createDisposition: Create.CreateDisposition,
    createOptions: Create.CreateOptions,
    name: String
  ) async throws -> Create.Response {
    let request = Create.Request(
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      desiredAccess: desiredAccess,
      fileAttributes: fileAttributes,
      shareAccess: shareAccess,
      createDisposition: createDisposition,
      createOptions: createOptions,
      name: name
    )

    return try await send(request)
  }

  public func read(fileId: Data, offset: UInt64) async throws -> Read.Response {
    try await read(fileId: fileId, offset: offset, length: maxReadSize)
  }

  public func read(fileId: Data, offset: UInt64, length: UInt32) async throws -> Read.Response {
    try await read(fileId: fileId, offset: offset, length: length, tree: self)
  }

  /// Reads on this connection, addressing the tree connected by `tree`, which
  /// may be another channel of the same session.
  func read(fileId: Data, offset: UInt64, length: UInt32, tree: Session) async throws -> Read.Response {
    let readSize = min(length, maxReadSize)
    let creditSize = creditSize(size: readSize)

    let request = Read.Request(
      creditCharge: creditSize,
      messageId: messageId.next(count: UInt64(creditSize)),
      treeId: tree.treeId,
      sessionId: sessionId,
      fileId: fileId,
      offset: offset,
      length: readSize,
      flags: connection.messageCompressor != nil ? Read.Flags.requestCompressed.rawValue : 0
    )

    let encrypt = shouldEncrypt(tree: tree)
    let responses = try await transmit(sign(request.encoded(), encrypt: encrypt), encrypt: encrypt)
    return Read.Response(data: responses[0])
  }

  @discardableResult
  public func write(data: Data, fileId: Data, offset: UInt64) async throws -> Write.Response {
    try await write(data: data, fileId: fileId, offset: offset, length: maxWriteSize)
  }

  @discardableResult
  public func write(data: Data, fileId: Data, offset: UInt64, length: UInt32) async throws -> Write.Response {
    try await write(data: data, fileId: fileId, offset: offset, length: length, tree: self)
  }

  /// Writes on this connection, addressing the tree connected by `tree`, which
  /// may be another channel of the same session.
  func write(data: Data, fileId: Data, offset: UInt64, length: UInt32, tree: Session) async throws -> Write.Response {
    let writeSize = min(length, maxWriteSize)
    let creditSize = creditSize(size: writeSize)

    let request = Write.Request(
      creditCharge: creditSize,
      messageId: messageId.next(count: UInt64(creditSize)),
      treeId: tree.treeId,
      sessionId: sessionId,
      fileId: fileId,
      offset: offset,
      data: data
    )

    let encrypt = shouldEncrypt(tree: tree)
    let responses = try await transmit(sign(request.encoded(), encrypt: encrypt), encrypt: encrypt)
    return Write.Response(data: responses[0])
  }

  @discardableResult
  public func close(fileId: Data) async throws -> Close.Response {
    let request = Close.Request(
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: fileId
    )

    return try await send(request)
  }

  public func queryDirectory(path: String, pattern: String) async throws -> [FileDirectoryInformation] {
    let createRequest = Create.Request(
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      desiredAccess: [.readData, .readAttributes, .synchronize],
      fileAttributes: [.directory],
      shareAccess: [.read, .write, .delete],
      createDisposition: .open,
      createOptions: [.directoryFile],
      name: path
    )

    let outputBufferLength = min(1048576, maxTransactSize)
    let creditSize = creditSize(size: outputBufferLength)
    let fileInformationClass = QueryDirectory.FileInformationClass.fileDirectoryInformation

    let queryDirectoryRequest = QueryDirectory.Request(
      creditCharge: creditSize,
      headerFlags: [.relatedOperations],
      messageId: messageId.next(count: UInt64(creditSize)),
      treeId: treeId,
      sessionId: sessionId,
      fileInformationClass: fileInformationClass,
      fileId: temporaryUUID,
      fileName: pattern,
      outputBufferLength: outputBufferLength
    )

    let (createResponse, queryDirectoryResponse) = try await send(createRequest, queryDirectoryRequest)

    var files: [FileDirectoryInformation] = queryDirectoryResponse.files()

    if NTStatus(createResponse.header.status) != .noMoreFiles {
      repeat {
        let fileId = createResponse.fileId

        let queryDirectoryRequest = QueryDirectory.Request(
          creditCharge: creditSize,
          messageId: messageId.next(count: UInt64(creditSize)),
          treeId: treeId,
          sessionId: sessionId,
          fileInformationClass: fileInformationClass,
          flags: [],
          fileId: fileId,
          fileName: pattern,
          outputBufferLength: outputBufferLength
        )

        let queryDirectoryResponse = try await send(queryDirectoryRequest)
        files.append(contentsOf: queryDirectoryResponse.files())

        if NTStatus(queryDirectoryResponse.header.status) == .noMoreFiles {
          break
        }
      } while true
    }

    try await close(fileId: createResponse.fileId)

    return files
  }

  public func fileStat(path: String) async throws -> Create.Response {
    let createRequest = Create.Request(
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      desiredAccess: [.readData, .readAttributes, .synchronize],
      fileAttributes: [],
      shareAccess: [.read, .write, .delete],
      createDisposition: .open,
      createOptions: [],
      name: path
    )
    let closeRequest = Close.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: temporaryUUID
    )

    let (response, _) = try await send(createRequest, closeRequest)
    return response
  }

  public func existFile(path: String) async throws -> Bool {
    do {
      _ = try await fileStat(path: path)
      return true
    } catch let error as ErrorResponse {
      if NTStatus(error.header.status) == .objectNameNotFound {
        return false
      }
      throw error
    }
  }

  public func existDirectory(path: String) async throws -> Bool {
    do {
      let stat = try await fileStat(path: path)
      return stat.fileAttributes.contains(.directory)
    } catch let error as ErrorResponse {
      if NTStatus(error.header.status) == .objectNameNotFound {
        return false
      }
      throw error
    }
  }

  public func queryInfo(path: String, infoType: InfoType = .file, fileInfoClass: FileInfoClass = .fileAllInformation) async throws -> QueryInfo.Response {
    let createRequest = Create.Request(
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      desiredAccess: [.readAttributes],
      fileAttributes: [],
      shareAccess: [.read],
      createDisposition: .open,
      createOptions: [],
      name: path
    )
    let queryInfoRequest = QueryInfo.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      infoType: infoType,
      fileInfoClass: fileInfoClass,
      fileId: temporaryUUID
    )
    let closeRequest = Close.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: temporaryUUID
    )

    let (_, response, _) = try await send(createRequest, queryInfoRequest, closeRequest)
    return response
  }

  /// Queries the self-relative Windows security descriptor for a file or directory.
  public func querySecurityDescriptor(
    path: String,
    securityInformation: SecurityDescriptor = [.owner, .group, .dacl]
  ) async throws -> Data {
    let createRequest = Create.Request(
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      desiredAccess: [.readControl],
      fileAttributes: [],
      shareAccess: [.read, .write, .delete],
      createDisposition: .open,
      createOptions: [],
      name: path
    )
    let queryInfoRequest = QueryInfo.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      infoType: .security,
      fileInfoClass: .none,
      outputBufferLength: 65_536,
      additionalInformation: UInt32(securityInformation.rawValue),
      fileId: temporaryUUID
    )
    let closeRequest = Close.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: temporaryUUID
    )

    let (_, response, _) = try await send(createRequest, queryInfoRequest, closeRequest)
    return response.buffer
  }

  @discardableResult
  public func createDirectory(path: String) async throws -> Create.Response {
    let response = try await create(
      desiredAccess: [.readData, .readAttributes],
      fileAttributes: [],
      shareAccess: [.read, .write, .delete],
      createDisposition: .create,
      createOptions: [.directoryFile],
      name: path.precomposedStringWithCanonicalMapping
    )
    try await close(fileId: response.fileId)
    return response
  }

  public func deleteDirectory(path: String) async throws {
    let files = try await queryDirectory(path: path, pattern: "*")
    for file in files {
      guard file.fileName != "." && file.fileName != ".." else {
        continue
      }

      let subpath = Pathname.join(path, file.fileName)
      if file.fileAttributes.contains(.directory) {
        try await deleteDirectory(path: subpath)
      } else {
        try await deleteFile(path: subpath)
      }
    }

    let createRequest = Create.Request(
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      desiredAccess: [.readAttributes, .delete, .synchronize],
      fileAttributes: [.directory],
      shareAccess: [],
      createDisposition: .open,
      createOptions: [.directoryFile],
      name: path
    )
    let setInfoRequest = SetInfo.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: temporaryUUID,
      infoType: .file,
      fileInformation: FileDispositionInformation(deletePending: true)
    )
    let closeRequest = Close.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: temporaryUUID
    )

    _ = try await send(createRequest, setInfoRequest, closeRequest)
  }

  public func deleteFile(path: String) async throws {
    let createRequest = Create.Request(
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      desiredAccess: [.readAttributes, .delete, .synchronize],
      fileAttributes: [.normal],
      shareAccess: [],
      createDisposition: .open,
      createOptions: [],
      name: path
    )
    let setInfoRequest = SetInfo.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: temporaryUUID,
      infoType: .file,
      fileInformation: FileDispositionInformation(deletePending: true)
    )
    let closeRequest = Close.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: temporaryUUID
    )

    _ = try await send(createRequest, setInfoRequest, closeRequest)
  }

  public func move(from: String, to: String) async throws {
    let createRequest = Create.Request(
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      desiredAccess: [.readAttributes, .delete, .synchronize],
      fileAttributes: [.normal],
      shareAccess: [],
      createDisposition: .open,
      createOptions: [],
      name: from
    )
    let setInfoRequest = SetInfo.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: temporaryUUID,
      infoType: .file,
      fileInformation: FileRenameInformation(fileName: to.precomposedStringWithCanonicalMapping)
    )
    let closeRequest = Close.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: temporaryUUID
    )

    _ = try await send(createRequest, setInfoRequest, closeRequest)
  }

  @discardableResult
  public func setInfo(path: String, _ info: FileInformationClass) async throws -> SetInfo.Response {
    let createRequest = Create.Request(
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      desiredAccess: [.readAttributes, .writeAttributes, .synchronize],
      fileAttributes: [],
      shareAccess: [.read, .write, .delete],
      createDisposition: .open,
      createOptions: [],
      name: path
    )
    let setInfoRequest = SetInfo.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: temporaryUUID,
      infoType: .file,
      fileInformation: info
    )
    let closeRequest = Close.Request(
      headerFlags: [.relatedOperations],
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: temporaryUUID
    )

    let (_, response, _) = try await send(createRequest, setInfoRequest, closeRequest)
    return response
  }

  @discardableResult
  public func flush(fileId: Data) async throws -> Flush.Response {
    let request = Flush.Request(
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      fileId: fileId
    )

    return try await send(request)
  }

  @discardableResult
  public func echo() async throws -> Echo.Response {
    let request = Echo.Request(
      messageId: messageId.next(),
      sessionId: sessionId
    )

    return try await send(request)
  }

  @discardableResult
  func bind(fileId: Data) async throws -> IOCtl.Response {
    let input = DCERPC.Bind(
      callID: 1,
      context: DCERPC.ContextList(
        items: [
          DCERPC.PresentationContext(
            contextID: 0,
            abstractSyntax: DCERPC.AbstractSyntax(),
            transferSyntaxes: [
              DCERPC.TransferSyntax()
            ]
          )
        ]
      )
    )

    let creditSize = creditSize(size: maxReadSize)
    let request = IOCtl.Request(
      creditCharge: creditSize,
      messageId: messageId.next(count: UInt64(creditSize)),
      treeId: treeId,
      sessionId: sessionId,
      ctlCode: .pipeTransceive,
      fileId: fileId,
      input: input.encoded(),
      output: Data()
    )

    return try await send(request)
  }

  func netShareEnum(fileId: Data) async throws -> IOCtl.Response {
    let netShareEnum = NetShareEnum(serverName: connection.host)

    let input = DCERPC.Request(
      callID: 0,
      opnum: .netrShareEnum,
      stub: netShareEnum.encoded()
    )

    let creditSize = creditSize(size: maxReadSize)
    let request = IOCtl.Request(
      creditCharge: creditSize,
      messageId: messageId.next(count: UInt64(creditSize)),
      treeId: treeId,
      sessionId: sessionId,
      ctlCode: .pipeTransceive,
      fileId: fileId,
      input: input.encoded(),
      output: Data()
    )

    return try await send(request)
  }

  private func send<Request: Message.Request>(_ message: Request) async throws -> Request.Response {
    let responses = try await transmit(sign(message.encoded()))
    return Request.Response(data: responses[0])
  }

#if compiler(>=5.9)
  private func send<each Request: Message.Request>(_ messages: repeat each Request) async throws -> (repeat (each Request).Response) {
    var count = 0
    for _ in repeat each messages {
      count += 1
    }

    var packet = Data()
    var index = 0
    for message in repeat each messages {
      let data = message.encoded()
      let alignment = Data(count: 8 - data.count % 8)
      if index < count - 1 {
        let body = data + alignment
        var header = Header(data: body[..<64])
        let payload = data[64...]

        header.nextCommand = UInt32(body.count)

        packet += try sign(header.encoded() + payload + alignment)
      } else {
        packet += try sign(data + alignment)
      }

      index += 1
    }

    let responses = try await transmit(packet)

    var iterator = 0
    func respond<R: Message.Request>(requestType: R.Type) -> R.Response {
      let response = R.Response(data: responses[iterator])
      iterator += 1
      return response
    }

    return (repeat respond(requestType: (each Request).self))
  }
#else
  private func send<R1: Message.Request, R2: Message.Request>(_ m1: R1, _ m2: R2) async throws -> (R1.Response, R2.Response) {
    let responses = try await send(m1.encoded(), m2.encoded())
    return (R1.Response(data: responses[0]), R2.Response(data: responses[1]))
  }

  private func send<R1: Message.Request, R2: Message.Request, R3: Message.Request>(_ m1: R1, _ m2: R2, _ m3: R3) async throws -> (R1.Response, R2.Response, R3.Response) {
    let responses = try await send(m1.encoded(), m2.encoded(), m3.encoded())
    return (R1.Response(data: responses[0]), R2.Response(data: responses[1]), R3.Response(data: responses[2]))
  }

  private func send(_ packets: Data...) async throws -> [Data] {
    return try await transmit(
      packets.enumerated().reduce(into: Data()) {
        let alignment = Data(count: 8 - $1.element.count % 8)
        if $1.offset < packets.count - 1 {
          let packet = $1.element + alignment
          var header = Header(data: packet[..<64])
          let payload = $1.element[64...]

          header.nextCommand = UInt32(packet.count)

          $0 += try sign(header.encoded() + payload + alignment)
        } else {
          $0 += try sign($1.element + alignment)
        }
      }
    )
  }
#endif

  /// Compresses and encrypts an already signed packet as needed, sends it,
  /// then verifies each response before checking its status.
  private func transmit(_ packet: Data, policy: SignaturePolicy = .standard, encrypt: Bool? = nil) async throws -> [Data] {
    let encrypt = encrypt ?? isEncrypted
    let response = try await connection.exchange(encryptIfNeeded(compressIfNeeded(packet), encrypt: encrypt))
    for message in response.messages {
      try verify(message, encrypted: response.encrypted, expectEncrypted: encrypt, policy: policy)
    }
    try response.check()
    return response.messages
  }

  func sign(_ packet: Data, force: Bool = false, encrypt: Bool? = nil) throws -> Data {
    guard !(encrypt ?? isEncrypted), let signingKey, !isAnonymous else {
      return packet
    }

    var header = Header(data: packet[..<64])
    let payload = packet[64...]

    // SMB 3.1.1 requires TREE_CONNECT to be signed even when signing is not
    // otherwise required (MS-SMB2 3.2.4.1.1).
    let isTreeConnect = header.command == Header.Command.treeConnect.rawValue
    guard force || signingRequired || (dialect == .smb311 && isTreeConnect) else {
      return packet
    }

    header.flags = header.flags.union(.signed)
    header.signature = Data(count: 16)
    header.signature = try signature(for: header.encoded() + payload, key: signingKey)

    return header.encoded() + payload
  }

  enum SignaturePolicy {
    /// Verify signed responses; when signing is required, successful
    /// responses must be signed.
    case standard
    /// Verify the signature only if the response is signed.
    case ifSigned
    /// The response must be signed (or encrypted).
    case required
  }

  /// Verifies a response signature (MS-SMB2 3.2.5.1.3).
  func verify(_ message: Data, encrypted: Bool, expectEncrypted: Bool? = nil, policy: SignaturePolicy) throws {
    guard message.count >= 64 else {
      throw SecurityError.signatureMismatch
    }
    let header = Header(data: Data(message.prefix(64)))
    let status = NTStatus(header.status)

    if (expectEncrypted ?? isEncrypted) && !encrypted && !(status == .pending) {
      throw SecurityError.unencryptedResponse
    }
    // Encrypted responses are authenticated by the cipher.
    guard !encrypted, let signingKey, !isAnonymous else {
      return
    }

    if header.flags.contains(.signed) {
      var unsigned = Data(message)
      unsigned.replaceSubrange(48..<64, with: Data(count: 16))
      let expected = try signature(for: unsigned, key: signingKey)
      guard expected == header.signature else {
        throw SecurityError.signatureMismatch
      }
      return
    }

    switch policy {
    case .ifSigned:
      return
    case .required:
      throw SecurityError.unsignedResponse
    case .standard:
      // Error responses may legitimately be unsigned (e.g. when the session
      // has expired); they carry no data, so only successful responses are
      // required to be signed.
      if signingRequired && Connection.isSuccess(message) {
        throw SecurityError.unsignedResponse
      }
    }
  }

  /// Computes the signature of a message whose Signature field is zeroed
  /// (MS-SMB2 3.1.4.1).
  private func signature(for message: Data, key: Data) throws -> Data {
    let header = Header(data: Data(message.prefix(64)))

    switch (dialect, signingAlgorithm) {
    case (.smb202, _), (.smb210, _), (.none, _), (_, .hmacSHA256):
      return Data(Crypto.hmacSHA256(key: key, data: message)[..<16])
    case (_, .aesCMAC):
      return Crypto.aesCMAC(key: key, data: message)
    case (_, .aesGMAC):
      // Nonce: MessageId followed by a 4-byte field whose bit 0 marks a
      // server-to-client message and bit 1 a CANCEL request.
      var role: UInt32 = 0
      if header.flags.contains(.serverToRedir) {
        role |= 0x1
      }
      if header.command == Header.Command.cancel.rawValue {
        role |= 0x2
      }
      var nonce = Data()
      nonce += header.messageId
      nonce += role
      return try Crypto.aesGMAC(key: key, nonce: nonce, data: message)
    }
  }

  /// Compresses a single WRITE request when SMB 3.1.1 compression was
  /// negotiated and it pays off.
  private func compressIfNeeded(_ packet: Data) -> Data {
    guard let messageCompressor = connection.messageCompressor, packet.count >= 64 else {
      return packet
    }
    let header = Header(data: Data(packet.prefix(64)))
    guard header.command == Header.Command.write.rawValue, header.nextCommand == 0 else {
      return packet
    }
    return messageCompressor.compress(packet) ?? packet
  }

  private func encryptIfNeeded(_ packet: Data, encrypt: Bool? = nil) throws -> Data {
    guard encrypt ?? isEncrypted, let messageCipher = connection.messageCipher else {
      return packet
    }
    return try messageCipher.encrypt(packet)
  }

  private func shouldEncrypt(tree: Session) -> Bool {
    connection.messageCipher != nil && (tree.encryptData || tree.encryptTree)
  }

  /// Test hook: configures signing without a server.
  func configureSigning(dialect: Negotiate.Dialects, algorithm: Negotiate.SigningAlgorithm, key: Data, required: Bool) {
    self.dialect = dialect
    signingAlgorithm = algorithm
    signingKey = key
    signingRequired = required
    isAnonymous = false
  }

  // MARK: - Multichannel

  /// Whether the server supports binding more channels to this session.
  public var isMultiChannelSupported: Bool {
    guard let dialect, dialect.rawValue >= Negotiate.Dialects.smb300.rawValue, let negotiateInfo else {
      return false
    }
    return negotiateInfo.clientCapabilities.contains(.multiChannel)
      && negotiateInfo.serverCapabilities.contains(.multiChannel)
      && credentials != nil
      && !isAnonymous
  }

  /// Opens another connection to the server and binds it to this session as
  /// an additional channel (MS-SMB2 3.2.4.2.3). Reads and writes through
  /// FileReader and FileWriter are then spread over all channels.
  @discardableResult
  public func bindChannel(host: String? = nil, port: Int? = nil) async throws -> Session {
    guard isMultiChannelSupported, let dialect, let negotiateInfo, let credentials, let signingKey else {
      throw MultiChannelError.notSupported
    }

    let channel = Session(
      Connection(host: host ?? server, port: port ?? connection.port, transport: connection.transport)
    )
    channel.clientGuid = clientGuid
    channel.supportedCiphers = cipher.map { [$0] } ?? supportedCiphers
    channel.supportedSigningAlgorithms = [signingAlgorithm]
    channel.supportedCompressionAlgorithms = supportedCompressionAlgorithms

    do {
      try await channel.connect()
      try await channel.negotiate(securityMode: negotiateInfo.clientSecurityMode, dialects: [dialect])
      guard
        channel.dialect == dialect,
        channel.negotiateInfo?.serverGuid == negotiateInfo.serverGuid,
        channel.cipher == cipher,
        channel.signingAlgorithm == signingAlgorithm
      else {
        throw MultiChannelError.negotiationMismatch
      }
      try await channel.bind(to: self, credentials: credentials, sessionSigningKey: signingKey)
    } catch {
      channel.disconnect()
      throw error
    }

    channel.onDisconnected = { [weak self, weak channel] _ in
      guard let self, let channel else { return }
      self.channels.removeAll { $0 === channel }
    }
    channels.append(channel)
    return channel
  }

  /// Authenticates again on this (new) connection with SMB2_SESSION_FLAG_BINDING.
  /// Binding requests are signed with the session's signing key; the final
  /// response with the new channel's signing key.
  private func bind(to primary: Session, credentials: Credentials, sessionSigningKey: Data) async throws {
    sessionId = primary.sessionId
    signingKey = sessionSigningKey
    signingRequired = primary.signingRequired
    isAnonymous = false

    var preauthIntegrityHashValue = self.preauthIntegrityHashValue
    func updatePreauthIntegrityHash(_ message: Data) {
      guard dialect == .smb311 else { return }
      preauthIntegrityHashValue = Crypto.sha512(preauthIntegrityHashValue + message)
    }

    let negotiateMessage = NTLM.NegotiateMessage(
      domainName: credentials.domain,
      workstationName: credentials.workstation
    )
    let securityBuffer = negotiateMessage.encoded()

    let request = SessionSetup.Request(
      messageId: messageId.next(),
      sessionId: sessionId,
      flags: [.binding],
      securityMode: [.signingEnabled],
      capabilities: [],
      previousSessionId: 0,
      securityBuffer: securityBuffer
    )
    let requestData = try sign(request.encoded(), force: true, encrypt: false)
    updatePreauthIntegrityHash(requestData)
    let response = try await connection.exchange(requestData)
    let responseData = response.messages[0]
    guard NTStatus(Header(data: Data(responseData.prefix(64))).status) == .moreProcessingRequired else {
      try response.check()
      throw MultiChannelError.bindingFailed
    }
    try verify(responseData, encrypted: false, expectEncrypted: false, policy: .ifSigned)
    updatePreauthIntegrityHash(responseData)

    let challengeMessage = NTLM.ChallengeMessage(data: SessionSetup.Response(data: responseData).buffer)
    let sessionKey = Crypto.randomBytes(count: 16)
    let authenticateMessage = challengeMessage.authenticateMessage(
      username: credentials.username,
      password: credentials.password,
      domain: credentials.domain,
      workstation: credentials.workstation,
      negotiateMessage: securityBuffer,
      signingKey: sessionKey
    )

    // A new connection starts with a single credit. Ask for enough that the
    // first large READ/WRITE (up to 128 credits each) fits; Samba drops the
    // connection when a request is charged more credits than granted.
    let authenticateRequest = SessionSetup.Request(
      messageId: messageId.next(),
      sessionId: sessionId,
      creditRequest: 256,
      flags: [.binding],
      securityMode: [.signingEnabled],
      capabilities: [],
      previousSessionId: 0,
      securityBuffer: authenticateMessage.encoded()
    )
    let authenticateData = try sign(authenticateRequest.encoded(), force: true, encrypt: false)
    updatePreauthIntegrityHash(authenticateData)
    let finalResponse = try await connection.exchange(authenticateData)
    try finalResponse.check()

    switch dialect {
    case .smb311:
      signingKey = Crypto.kdf(key: sessionKey, label: Data("SMBSigningKey\0".utf8), context: preauthIntegrityHashValue, length: 16)
    default:
      signingKey = Crypto.kdf(key: sessionKey, label: Data("SMB2AESCMAC\0".utf8), context: Data("SmbSign\0".utf8), length: 16)
    }
    try verify(finalResponse.messages[0], encrypted: false, expectEncrypted: false, policy: .required)

    self.credentials = credentials
    treeId = primary.treeId
    connectedTree = primary.connectedTree
    encryptData = primary.encryptData
    encryptTree = primary.encryptTree
    connection.messageCipher = primary.connection.messageCipher
  }

  /// This session and its bound channels.
  var lanes: [Session] {
    [self] + channels
  }

  /// Reads `length` bytes from `offset`, fetching one chunk per channel
  /// concurrently, and hands the data to `deliver` in file order. Stops early
  /// at end of file. Returns the number of bytes read.
  @discardableResult
  func readInParallel(
    fileId: Data,
    offset: UInt64,
    length: UInt64,
    deliver: (Data) throws -> Void
  ) async throws -> UInt64 {
    let lanes = lanes
    let chunkSize = UInt64(maxReadSize)
    let end = offset + length
    var position = offset

    while position < end {
      let round = try await withThrowingTaskGroup(of: (Int, Data).self) { group in
        for (index, lane) in lanes.enumerated() {
          let start = position + UInt64(index) * chunkSize
          guard start < end else { break }
          let count = UInt32(min(chunkSize, end - start))
          group.addTask {
            let response = try await lane.read(fileId: fileId, offset: start, length: count, tree: self)
            return (index, response.buffer)
          }
        }
        var chunks = [(Int, Data)]()
        for try await chunk in group {
          chunks.append(chunk)
        }
        return chunks.sorted { $0.0 < $1.0 }.map { $0.1 }
      }

      for chunk in round {
        let requested = min(chunkSize, end - position)
        try deliver(chunk)
        position += UInt64(chunk.count)
        if UInt64(chunk.count) < requested {
          // Short read: end of file. Later chunks of this round are empty.
          return position - offset
        }
      }
    }
    return position - offset
  }

  /// Writes consecutive chunks starting at `offset`, one chunk per channel
  /// concurrently.
  func writeInParallel(fileId: Data, offset: UInt64, chunks: [Data]) async throws {
    let lanes = lanes
    var start = offset
    var index = 0
    while index < chunks.count {
      let round = Array(chunks[index..<min(index + lanes.count, chunks.count)])
      try await withThrowingTaskGroup(of: Void.self) { group in
        var chunkOffset = start
        for (lane, chunk) in zip(lanes, round) {
          let writeOffset = chunkOffset
          group.addTask {
            _ = try await lane.write(
              data: chunk,
              fileId: fileId,
              offset: writeOffset,
              length: UInt32(chunk.count),
              tree: self
            )
          }
          chunkOffset += UInt64(chunk.count)
        }
        try await group.waitForAll()
      }
      start += round.reduce(0) { $0 + UInt64($1.count) }
      index += round.count
    }
  }

  /// FSCTL_VALIDATE_NEGOTIATE_INFO (MS-SMB2 3.2.5.5 / 3.2.5.14.12): protects
  /// SMB 3.0 and 3.0.2 against a downgraded NEGOTIATE, which 3.1.1 covers
  /// with the preauth integrity hash instead.
  private func validateNegotiate() async throws {
    guard let negotiateInfo, signingKey != nil, !isAnonymous else {
      return
    }

    var input = Data()
    input += negotiateInfo.clientCapabilities.rawValue
    input += Data(from: clientGuid)
    input += negotiateInfo.clientSecurityMode.rawValue
    input += UInt16(negotiateInfo.dialects.count)
    for dialect in negotiateInfo.dialects {
      input += dialect.rawValue
    }

    let request = IOCtl.Request(
      creditCharge: 1,
      messageId: messageId.next(),
      treeId: treeId,
      sessionId: sessionId,
      ctlCode: .validateNegotiateInfo,
      fileId: Data(repeating: 0xFF, count: 16),
      input: input,
      output: Data()
    )

    let response = try await connection.exchange(encryptIfNeeded(sign(request.encoded(), force: true)))
    let message = response.messages[0]
    try verify(message, encrypted: response.encrypted, policy: .required)

    // A signed error means the server does not implement the FSCTL.
    guard Connection.isSuccess(message) else {
      return
    }

    let buffer = IOCtl.Response(data: message).buffer
    guard buffer.count >= 24 else {
      disconnect()
      throw NegotiateError.validationFailed
    }
    let reader = ByteReader(buffer)
    let capabilities: UInt32 = reader.read()
    let serverGuid: UUID = reader.read()
    let securityMode: UInt16 = reader.read()
    let dialect: UInt16 = reader.read()

    guard
      capabilities == negotiateInfo.serverCapabilities.rawValue,
      serverGuid == negotiateInfo.serverGuid,
      securityMode == negotiateInfo.serverSecurityMode.rawValue,
      dialect == negotiateInfo.dialectRevision
    else {
      disconnect()
      throw NegotiateError.validationFailed
    }
  }
}

struct NegotiateInfo {
  let clientCapabilities: Negotiate.Capabilities
  let clientSecurityMode: Negotiate.SecurityMode
  let dialects: [Negotiate.Dialects]
  let serverCapabilities: Negotiate.Capabilities
  let serverGuid: UUID
  let serverSecurityMode: Negotiate.SecurityMode
  let dialectRevision: UInt16
}

struct Credentials {
  let username: String?
  let password: String?
  let domain: String?
  let workstation: String?
}

public enum MultiChannelError: Error {
  case notSupported
  case negotiationMismatch
  case bindingFailed
}

public enum SecurityError: Error {
  case signatureMismatch
  case unsignedResponse
  case unencryptedResponse
}

public enum NegotiateError: Error {
  case missingPreauthIntegrity
  case validationFailed
}

private class SequenceNumber<I: UnsignedInteger & FixedWidthInteger> {
  var current: I = 0

  func next(count: I = 1) -> I {
    let next = current
    current &+= count
    return next
  }
}

private func creditSize(size: UInt32) -> UInt16 {
  UInt16(truncatingIfNeeded: (size - 1) / 65536 + 1)
}
