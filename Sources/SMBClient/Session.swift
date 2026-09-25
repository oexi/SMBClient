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

  public private(set) var dialect: Negotiate.Dialects?
  /// Ciphers offered for SMB 3.1.1, in order of preference.
  public var supportedCiphers: [Negotiate.Cipher] = [.aes128GCM, .aes128CCM, .aes256GCM, .aes256CCM]
  /// Signing algorithms offered for SMB 3.1.1, in order of preference.
  public var supportedSigningAlgorithms: [Negotiate.SigningAlgorithm] = [.aesGMAC, .aesCMAC]
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
    }
    let supportsSMB3 = dialects.contains { $0.rawValue >= Negotiate.Dialects.smb300.rawValue }

    let request = Negotiate.Request(
      messageId: messageId.next(),
      securityMode: securityMode,
      capabilities: supportsSMB3 ? [.encryption] : [],
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
    case .smb300, .smb302:
      signingAlgorithm = .aesCMAC
      cipher = response.capabilities.contains(.encryption) ? .aes128CCM : nil
    case .smb202, .smb210, .none:
      signingAlgorithm = .hmacSHA256
      cipher = nil
    }

    signingRequired = response.securityMode.contains(.signingRequired) || (securityMode.contains(.signingRequired) && response.securityMode.contains(.signingEnabled))

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
      let response = SessionSetup.Response(data: try await connection.send(requestData))

      sessionId = response.header.sessionId

      isAnonymous = ((username ?? "").isEmpty && (password ?? "").isEmpty)
        || !response.sessionFlags.isDisjoint(with: [.guest, .nullSession])

      try establishKeys(
        sessionKey: signingKey,
        preauthIntegrityHashValue: preauthIntegrityHashValue,
        sessionFlags: response.sessionFlags,
        requireEncryption: requireEncryption
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
    let readSize = min(length, maxReadSize)
    let creditSize = creditSize(size: readSize)

    let request = Read.Request(
      creditCharge: creditSize,
      messageId: messageId.next(count: UInt64(creditSize)),
      treeId: treeId,
      sessionId: sessionId,
      fileId: fileId,
      offset: offset,
      length: readSize
    )

    return try await send(request)
  }

  @discardableResult
  public func write(data: Data, fileId: Data, offset: UInt64) async throws -> Write.Response {
    try await write(data: data, fileId: fileId, offset: offset, length: maxWriteSize)
  }

  @discardableResult
  public func write(data: Data, fileId: Data, offset: UInt64, length: UInt32) async throws -> Write.Response {
    let writeSize = min(length, maxWriteSize)
    let creditSize = creditSize(size: writeSize)

    let request = Write.Request(
      creditCharge: creditSize,
      messageId: messageId.next(count: UInt64(creditSize)),
      treeId: treeId,
      sessionId: sessionId,
      fileId: fileId,
      offset: offset,
      data: data
    )

    return try await send(request)
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
    let packet = message.encoded()
    let data = try await connection.send(encryptIfNeeded(sign(packet)))
    let response = Request.Response(data: data)
    return response
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

    let responseData = try await connection.send(encryptIfNeeded(packet))
    let reader = ByteReader(responseData)

    var responses = [Data]()

    var header: Header
    var offset = 0

    repeat {
      responses.append(Data(responseData[offset...]))

      header = reader.read()

      offset += Int(header.nextCommand)
      reader.seek(to: offset)
    } while header.nextCommand != 0

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
    let data = try await send(m1.encoded(), m2.encoded())
    let r1 = R1.Response(data: data)
    let r2 = R2.Response(data: Data(data[r1.header.nextCommand...]))
    return (r1, r2)
  }

  private func send<R1: Message.Request, R2: Message.Request, R3: Message.Request>(_ m1: R1, _ m2: R2, _ m3: R3) async throws -> (R1.Response, R2.Response, R3.Response) {
    let data = try await send(m1.encoded(), m2.encoded(), m3.encoded())
    let r1 = R1.Response(data: data)
    let r2 = R2.Response(data: Data(data[r1.header.nextCommand...]))
    let r3 = R3.Response(data: Data(data[r2.header.nextCommand...]))
    return (r1, r2, r3)
  }

  private func send(_ packets: Data...) async throws -> Data {
    return try await connection.send(encryptIfNeeded(
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
    ))
  }
#endif

  private func sign(_ packet: Data) throws -> Data {
    guard !isEncrypted, let signingKey, !isAnonymous else {
      return packet
    }

    var header = Header(data: packet[..<64])
    let payload = packet[64...]

    // SMB 3.1.1 requires TREE_CONNECT to be signed even when signing is not
    // otherwise required (MS-SMB2 3.2.4.1.1).
    let isTreeConnect = header.command == Header.Command.treeConnect.rawValue
    guard signingRequired || (dialect == .smb311 && isTreeConnect) else {
      return packet
    }

    header.flags = header.flags.union(.signed)
    header.signature = Data(count: 16)
    let message = header.encoded() + payload

    switch (dialect, signingAlgorithm) {
    case (.smb202, _), (.smb210, _), (.none, _), (_, .hmacSHA256):
      header.signature = Crypto.hmacSHA256(key: signingKey, data: message)[..<16]
    case (_, .aesCMAC):
      header.signature = Crypto.aesCMAC(key: signingKey, data: message)
    case (_, .aesGMAC):
      // Nonce: MessageId followed by a 4-byte field whose bit 0 marks a
      // server-to-client message and bit 1 a CANCEL request.
      var nonce = Data()
      nonce += header.messageId
      nonce += UInt32(header.command == Header.Command.cancel.rawValue ? 0x2 : 0x0)
      header.signature = try Crypto.aesGMAC(key: signingKey, nonce: nonce, data: message)
    }

    return header.encoded() + payload
  }

  private func encryptIfNeeded(_ packet: Data) throws -> Data {
    guard isEncrypted, let messageCipher = connection.messageCipher else {
      return packet
    }
    return try messageCipher.encrypt(packet)
  }
}

public enum NegotiateError: Error {
  case missingPreauthIntegrity
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
