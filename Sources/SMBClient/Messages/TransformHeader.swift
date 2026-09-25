import Foundation

/// SMB2 TRANSFORM_HEADER (MS-SMB2 2.2.41), which wraps encrypted messages
/// for SMB 3.x.
public struct TransformHeader {
  public static let protocolId: UInt32 = 0x424D53FD
  public static let size = 52

  public let signature: Data
  public let nonce: Data
  public let originalMessageSize: UInt32
  public let flags: UInt16
  public let sessionId: UInt64

  init(signature: Data, nonce: Data, originalMessageSize: UInt32, sessionId: UInt64) {
    self.signature = signature
    self.nonce = nonce + Data(count: 16 - nonce.count)
    self.originalMessageSize = originalMessageSize
    self.flags = 0x0001 // Encrypted
    self.sessionId = sessionId
  }

  init(data: Data) {
    let reader = ByteReader(data)
    let _: UInt32 = reader.read()
    signature = reader.read(count: 16)
    nonce = reader.read(count: 16)
    originalMessageSize = reader.read()
    let _: UInt16 = reader.read()
    flags = reader.read()
    sessionId = reader.read()
  }

  /// The bytes from Nonce through SessionId, which are the additional
  /// authenticated data for the cipher.
  var associatedData: Data {
    var data = Data()
    data += nonce
    data += originalMessageSize
    data += UInt16(0)
    data += flags
    data += sessionId
    return data
  }

  func encoded() -> Data {
    var data = Data()
    data += TransformHeader.protocolId
    data += signature
    data += associatedData
    return data
  }

  static func isTransformMessage(_ data: Data) -> Bool {
    guard data.count >= 4 else {
      return false
    }
    return data.prefix(4).elementsEqual([0xFD, 0x53, 0x4D, 0x42])
  }
}

/// Encrypts and decrypts messages for an SMB 3.x session (MS-SMB2 3.1.4.3).
final class MessageCipher {
  let cipher: Negotiate.Cipher
  let sessionId: UInt64
  private let encryptionKey: Data
  private let decryptionKey: Data

  init(cipher: Negotiate.Cipher, sessionId: UInt64, encryptionKey: Data, decryptionKey: Data) {
    self.cipher = cipher
    self.sessionId = sessionId
    self.encryptionKey = encryptionKey
    self.decryptionKey = decryptionKey
  }

  func encrypt(_ message: Data) throws -> Data {
    let nonce = Crypto.randomBytes(count: cipher.nonceLength)
    let placeholder = TransformHeader(
      signature: Data(count: 16),
      nonce: nonce,
      originalMessageSize: UInt32(truncatingIfNeeded: message.count),
      sessionId: sessionId
    )
    let aad = placeholder.associatedData

    let sealed: (ciphertext: Data, tag: Data)
    switch cipher {
    case .aes128CCM, .aes256CCM:
      sealed = Crypto.aesCCMSeal(key: encryptionKey, nonce: nonce, plaintext: message, aad: aad)
    case .aes128GCM, .aes256GCM:
      sealed = try Crypto.aesGCMSeal(key: encryptionKey, nonce: nonce, plaintext: message, aad: aad)
    }

    let header = TransformHeader(
      signature: sealed.tag,
      nonce: nonce,
      originalMessageSize: placeholder.originalMessageSize,
      sessionId: sessionId
    )
    return header.encoded() + sealed.ciphertext
  }

  func decrypt(_ message: Data) throws -> Data {
    guard message.count >= TransformHeader.size else {
      throw MessageCipherError.malformedMessage
    }
    let header = TransformHeader(data: Data(message.prefix(TransformHeader.size)))
    let ciphertext = Data(message.dropFirst(TransformHeader.size))
    guard header.sessionId == sessionId, Int(header.originalMessageSize) == ciphertext.count else {
      throw MessageCipherError.malformedMessage
    }

    let nonce = Data(header.nonce.prefix(cipher.nonceLength))
    let aad = header.associatedData

    let plaintext: Data?
    switch cipher {
    case .aes128CCM, .aes256CCM:
      plaintext = Crypto.aesCCMOpen(key: decryptionKey, nonce: nonce, ciphertext: ciphertext, tag: header.signature, aad: aad)
    case .aes128GCM, .aes256GCM:
      plaintext = Crypto.aesGCMOpen(key: decryptionKey, nonce: nonce, ciphertext: ciphertext, tag: header.signature, aad: aad)
    }

    guard let plaintext else {
      throw MessageCipherError.authenticationFailed
    }
    return plaintext
  }
}

public enum MessageCipherError: Error {
  case malformedMessage
  case authenticationFailed
  case encryptionNotSupported
}
