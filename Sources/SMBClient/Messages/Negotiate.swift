import Foundation

public enum Negotiate {
  public struct Request: Message.Request {
    public typealias Response = Negotiate.Response

    public let header: Header
    public let structureSize: UInt16
    public let dialectCount: UInt16
    public let securityMode: SecurityMode
    public let reserved: UInt16
    public let capabilities: Capabilities
    public let clientGuid: UUID
    public let clientStartTime: UInt64
    public let dialects: [Dialects]
    public let padding: Data
    public let negotiateContextList: Data

    public init(
      headerFlags: Header.Flags = [],
      messageId: UInt64,
      securityMode: SecurityMode,
      capabilities: Capabilities = [],
      dialects: [Dialects],
      negotiateContexts: [NegotiateContext] = []
    ) {
      header = Header(
        creditCharge: 1,
        command: .negotiate,
        creditRequest: 0,
        flags: headerFlags,
        messageId: messageId,
        treeId: 0,
        sessionId: 0
      )

      structureSize  = 36
      dialectCount = UInt16(dialects.count)
      self.securityMode = securityMode
      reserved = 0
      self.capabilities = capabilities
      clientGuid = UUID()
      self.dialects = dialects

      if negotiateContexts.isEmpty || !dialects.contains(.smb311) {
        clientStartTime = 0
        padding = Data()
        negotiateContextList = Data()
      } else {
        // For SMB 3.1.1 the ClientStartTime field is NegotiateContextOffset (4 bytes),
        // NegotiateContextCount (2 bytes) and Reserved2 (2 bytes).
        let dialectsEnd = 64 + 36 + dialects.count * 2
        let padding = Data(count: (8 - dialectsEnd % 8) % 8)
        let offset = UInt64(dialectsEnd + padding.count)
        clientStartTime = offset | (UInt64(negotiateContexts.count) << 32)
        self.padding = padding

        var list = Data()
        for (index, context) in negotiateContexts.enumerated() {
          let encoded = context.encoded()
          list += encoded
          if index < negotiateContexts.count - 1 {
            list += Data(count: (8 - encoded.count % 8) % 8)
          }
        }
        negotiateContextList = list
      }
    }

    public func encoded() -> Data {
      var data = Data()

      data += header.encoded()

      data += structureSize
      data += dialectCount
      data += securityMode.rawValue
      data += reserved
      data += capabilities.rawValue
      data += Data(from: clientGuid)
      data += clientStartTime

      for dialect in dialects {
        data += dialect.rawValue
      }
      data += padding
      data += negotiateContextList

      return data
    }
  }

  public struct Response: Message.Response {
    public let header: Header
    public let structureSize: UInt16
    public let securityMode: SecurityMode
    public let dialectRevision: UInt16
    public let negotiateContextCount: UInt16
    public let serverGuid: UUID
    public let capabilities: Capabilities
    public let maxTransactSize: UInt32
    public let maxReadSize: UInt32
    public let maxWriteSize: UInt32
    public let systemTime: UInt64
    public let serverStartTime: UInt64
    public let securityBufferOffset: UInt16
    public let securityBufferLength: UInt16
    public let negotiateContextOffset: UInt32
    public let securityBuffer: Data
    public let negotiateContexts: [NegotiateContext]

    public init(data: Data) {
      let reader = ByteReader(data)

      header = reader.read()

      structureSize = reader.read()
      securityMode = SecurityMode(rawValue: reader.read())
      dialectRevision = reader.read()
      negotiateContextCount = reader.read()
      serverGuid = reader.read()
      capabilities = Capabilities(rawValue: reader.read())
      maxTransactSize = reader.read()
      maxReadSize = reader.read()
      maxWriteSize = reader.read()
      systemTime = reader.read()
      serverStartTime = reader.read()
      securityBufferOffset = reader.read()
      securityBufferLength = reader.read()
      negotiateContextOffset = reader.read()
      securityBuffer = reader.read(from: Int(securityBufferOffset), count: Int(securityBufferLength))

      var negotiateContexts = [NegotiateContext]()
      if dialectRevision == Dialects.smb311.rawValue && negotiateContextCount > 0 {
        var offset = Int(negotiateContextOffset)
        for _ in 0..<negotiateContextCount {
          guard offset + 8 <= data.count else { break }
          reader.seek(to: offset)
          let contextType: UInt16 = reader.read()
          let dataLength: UInt16 = reader.read()
          let _: UInt32 = reader.read()
          guard offset + 8 + Int(dataLength) <= data.count else { break }
          let contextData = reader.read(count: Int(dataLength))
          negotiateContexts.append(NegotiateContext(contextType: contextType, data: contextData))

          let length = 8 + Int(dataLength)
          offset += length + (8 - length % 8) % 8
        }
      }
      self.negotiateContexts = negotiateContexts
    }

    public var preauthIntegrityCapabilities: PreauthIntegrityCapabilities? {
      negotiateContexts.lazy.compactMap { PreauthIntegrityCapabilities(context: $0) }.first
    }

    public var encryptionCapabilities: EncryptionCapabilities? {
      negotiateContexts.lazy.compactMap { EncryptionCapabilities(context: $0) }.first
    }

    public var signingCapabilities: SigningCapabilities? {
      negotiateContexts.lazy.compactMap { SigningCapabilities(context: $0) }.first
    }
  }

  public struct SecurityMode: OptionSet, Sendable {
    public let rawValue: UInt16

    public init(rawValue: UInt16) {
      self.rawValue = rawValue
    }

    public static let signingEnabled = SecurityMode(rawValue: 0x0001)
    public static let signingRequired = SecurityMode(rawValue: 0x0002)
  }

  public struct Capabilities: OptionSet, Sendable {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
      self.rawValue = rawValue
    }

    public static let dfs = Capabilities(rawValue: 0x00000001)
    public static let leasing = Capabilities(rawValue: 0x00000002)
    public static let largeMtu = Capabilities(rawValue: 0x00000004)
    public static let multiChannel = Capabilities(rawValue: 0x00000008)
    public static let persistentHandles = Capabilities(rawValue: 0x00000010)
    public static let directoryLeasing = Capabilities(rawValue: 0x00000020)
    public static let encryption = Capabilities(rawValue: 0x00000040)
    public static let notifications = Capabilities(rawValue: 0x00000080)
  }

  public enum Dialects: UInt16 {
    case smb202 = 0x0202
    case smb210 = 0x0210
    case smb300 = 0x0300
    case smb302 = 0x0302
    case smb311 = 0x0311
  }

  public struct NegotiateContext {
    public let contextType: UInt16
    public let data: Data

    public init(contextType: UInt16, data: Data) {
      self.contextType = contextType
      self.data = data
    }

    public func encoded() -> Data {
      var encoded = Data()
      encoded += contextType
      encoded += UInt16(truncatingIfNeeded: data.count)
      encoded += UInt32(0)
      encoded += data
      return encoded
    }
  }

  public enum NegotiateContextType: UInt16 {
    case preauthIntegrityCapabilities = 0x0001
    case encryptionCapabilities = 0x0002
    case compressionCapabilities = 0x0003
    case netnameNegotiateContextId = 0x0005
    case transportCapabilities = 0x0006
    case rdmaTransformCapabilities = 0x0007
    case signingCapabilities = 0x0008
  }

  public enum HashAlgorithm: UInt16 {
    case sha512 = 0x0001
  }

  public enum Cipher: UInt16 {
    case aes128CCM = 0x0001
    case aes128GCM = 0x0002
    case aes256CCM = 0x0003
    case aes256GCM = 0x0004

    public var keyLength: Int {
      switch self {
      case .aes128CCM, .aes128GCM:
        return 16
      case .aes256CCM, .aes256GCM:
        return 32
      }
    }

    public var nonceLength: Int {
      switch self {
      case .aes128CCM, .aes256CCM:
        return 11
      case .aes128GCM, .aes256GCM:
        return 12
      }
    }
  }

  public enum SigningAlgorithm: UInt16 {
    case hmacSHA256 = 0x0000
    case aesCMAC = 0x0001
    case aesGMAC = 0x0002
  }

  public struct PreauthIntegrityCapabilities {
    public let hashAlgorithms: [HashAlgorithm]
    public let salt: Data

    public init(hashAlgorithms: [HashAlgorithm], salt: Data) {
      self.hashAlgorithms = hashAlgorithms
      self.salt = salt
    }

    init?(context: NegotiateContext) {
      guard context.contextType == NegotiateContextType.preauthIntegrityCapabilities.rawValue, context.data.count >= 4 else {
        return nil
      }
      let reader = ByteReader(context.data)
      let count: UInt16 = reader.read()
      let saltLength: UInt16 = reader.read()
      guard context.data.count >= 4 + Int(count) * 2 + Int(saltLength) else {
        return nil
      }
      hashAlgorithms = (0..<count).compactMap { _ in HashAlgorithm(rawValue: reader.read()) }
      salt = reader.read(count: Int(saltLength))
    }

    public var context: NegotiateContext {
      var data = Data()
      data += UInt16(hashAlgorithms.count)
      data += UInt16(salt.count)
      for algorithm in hashAlgorithms {
        data += algorithm.rawValue
      }
      data += salt
      return NegotiateContext(contextType: NegotiateContextType.preauthIntegrityCapabilities.rawValue, data: data)
    }
  }

  public struct EncryptionCapabilities {
    public let ciphers: [Cipher]

    public init(ciphers: [Cipher]) {
      self.ciphers = ciphers
    }

    init?(context: NegotiateContext) {
      guard context.contextType == NegotiateContextType.encryptionCapabilities.rawValue, context.data.count >= 2 else {
        return nil
      }
      let reader = ByteReader(context.data)
      let count: UInt16 = reader.read()
      guard context.data.count >= 2 + Int(count) * 2 else {
        return nil
      }
      ciphers = (0..<count).compactMap { _ in Cipher(rawValue: reader.read()) }
    }

    public var context: NegotiateContext {
      var data = Data()
      data += UInt16(ciphers.count)
      for cipher in ciphers {
        data += cipher.rawValue
      }
      return NegotiateContext(contextType: NegotiateContextType.encryptionCapabilities.rawValue, data: data)
    }
  }

  public struct SigningCapabilities {
    public let signingAlgorithms: [SigningAlgorithm]

    public init(signingAlgorithms: [SigningAlgorithm]) {
      self.signingAlgorithms = signingAlgorithms
    }

    init?(context: NegotiateContext) {
      guard context.contextType == NegotiateContextType.signingCapabilities.rawValue, context.data.count >= 2 else {
        return nil
      }
      let reader = ByteReader(context.data)
      let count: UInt16 = reader.read()
      guard context.data.count >= 2 + Int(count) * 2 else {
        return nil
      }
      signingAlgorithms = (0..<count).compactMap { _ in SigningAlgorithm(rawValue: reader.read()) }
    }

    public var context: NegotiateContext {
      var data = Data()
      data += UInt16(signingAlgorithms.count)
      for algorithm in signingAlgorithms {
        data += algorithm.rawValue
      }
      return NegotiateContext(contextType: NegotiateContextType.signingCapabilities.rawValue, data: data)
    }
  }
}
