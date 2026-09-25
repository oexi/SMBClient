import Foundation
import CommonCrypto
import CryptoKit

extension Crypto {
  public static func sha512(_ data: Data) -> Data {
    var digest = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
    data.withUnsafeBytes {
      _ = CC_SHA512($0.baseAddress, CC_LONG(data.count), &digest)
    }
    return Data(digest)
  }

  /// SP800-108 KDF in counter mode with HMAC-SHA256, as used by SMB 3.x
  /// (MS-SMB2 3.1.4.2). `label` and `context` are passed with their trailing NUL.
  public static func kdf(key: Data, label: Data, context: Data, length: Int) -> Data {
    var input = Data()
    input += UInt32(1).bigEndian
    input += label
    input += UInt8(0)
    input += context
    input += UInt32(length * 8).bigEndian
    return Data(hmacSHA256(key: key, data: input).prefix(length))
  }

  /// AES-CMAC (RFC 4493).
  public static func aesCMAC(key: Data, data: Data) -> Data {
    let blockSize = kCCBlockSizeAES128
    let l = aesECB(key: key, block: Data(count: blockSize))
    let k1 = cmacSubkey(l)
    let k2 = cmacSubkey(k1)

    let blockCount = max(1, (data.count + blockSize - 1) / blockSize)
    let isComplete = !data.isEmpty && data.count % blockSize == 0
    let lastStart = data.startIndex + (blockCount - 1) * blockSize

    var last = Data(data[lastStart...])
    if isComplete {
      last = xor(last, k1)
    } else {
      last.append(0x80)
      last.append(Data(count: blockSize - last.count))
      last = xor(last, k2)
    }

    var x = Data(count: blockSize)
    if blockCount > 1 {
      let head = aesCBC(key: key, iv: x, data: Data(data[data.startIndex..<lastStart]))
      x = Data(head.suffix(blockSize))
    }
    return aesECB(key: key, block: xor(x, last))
  }

  /// AES-CCM (RFC 3610) with a 16-byte tag. Returns the ciphertext and tag.
  public static func aesCCMSeal(key: Data, nonce: Data, plaintext: Data, aad: Data) -> (ciphertext: Data, tag: Data) {
    let tag = ccmMAC(key: key, nonce: nonce, plaintext: plaintext, aad: aad)
    let s0 = aesECB(key: key, block: ccmCounterBlock(nonce: nonce, counter: 0))
    let ciphertext = aesCTR(key: key, iv: ccmCounterBlock(nonce: nonce, counter: 1), data: plaintext)
    return (ciphertext, xor(tag, s0))
  }

  public static func aesCCMOpen(key: Data, nonce: Data, ciphertext: Data, tag: Data, aad: Data) -> Data? {
    let plaintext = aesCTR(key: key, iv: ccmCounterBlock(nonce: nonce, counter: 1), data: ciphertext)
    let s0 = aesECB(key: key, block: ccmCounterBlock(nonce: nonce, counter: 0))
    let expected = xor(ccmMAC(key: key, nonce: nonce, plaintext: plaintext, aad: aad), s0)
    guard constantTimeEqual(expected, tag) else {
      return nil
    }
    return plaintext
  }

  public static func aesGCMSeal(key: Data, nonce: Data, plaintext: Data, aad: Data) throws -> (ciphertext: Data, tag: Data) {
    let box = try AES.GCM.seal(
      plaintext,
      using: SymmetricKey(data: key),
      nonce: AES.GCM.Nonce(data: nonce),
      authenticating: aad
    )
    return (box.ciphertext, box.tag)
  }

  public static func aesGCMOpen(key: Data, nonce: Data, ciphertext: Data, tag: Data, aad: Data) -> Data? {
    guard
      let nonce = try? AES.GCM.Nonce(data: nonce),
      let box = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
    else {
      return nil
    }
    return try? AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad)
  }

  /// AES-GMAC: AES-GCM over an empty plaintext, authenticating `data`.
  public static func aesGMAC(key: Data, nonce: Data, data: Data) throws -> Data {
    try aesGCMSeal(key: key, nonce: nonce, plaintext: Data(), aad: data).tag
  }

  // MARK: - Private

  private static func ccmMAC(key: Data, nonce: Data, plaintext: Data, aad: Data) -> Data {
    let blockSize = kCCBlockSizeAES128
    let lengthSize = 15 - nonce.count

    var b0 = Data()
    let flags = (aad.isEmpty ? 0 : 0x40) | (((16 - 2) / 2) << 3) | (lengthSize - 1)
    b0 += UInt8(flags)
    b0 += nonce
    for i in (0..<lengthSize).reversed() {
      b0 += UInt8(truncatingIfNeeded: plaintext.count >> (i * 8))
    }

    var input = b0
    if !aad.isEmpty {
      input += UInt16(aad.count).bigEndian
      input += aad
      input += Data(count: (blockSize - input.count % blockSize) % blockSize)
    }
    input += plaintext
    input += Data(count: (blockSize - input.count % blockSize) % blockSize)

    let cbc = aesCBC(key: key, iv: Data(count: blockSize), data: input)
    return Data(cbc.suffix(blockSize))
  }

  private static func ccmCounterBlock(nonce: Data, counter: UInt32) -> Data {
    let lengthSize = 15 - nonce.count
    var block = Data()
    block += UInt8(lengthSize - 1)
    block += nonce
    for i in (0..<lengthSize).reversed() {
      block += UInt8(truncatingIfNeeded: Int(counter) >> (i * 8))
    }
    return block
  }

  private static func cmacSubkey(_ input: Data) -> Data {
    var output = Data(count: input.count)
    var carry: UInt8 = 0
    for i in (0..<input.count).reversed() {
      let byte = input[input.startIndex + i]
      output[i] = (byte << 1) | carry
      carry = byte >> 7
    }
    if carry != 0 {
      output[output.count - 1] ^= 0x87
    }
    return output
  }

  private static func aesECB(key: Data, block: Data) -> Data {
    aes(mode: CCMode(kCCModeECB), key: key, iv: nil, data: block)
  }

  private static func aesCBC(key: Data, iv: Data, data: Data) -> Data {
    aes(mode: CCMode(kCCModeCBC), key: key, iv: iv, data: data)
  }

  private static func aesCTR(key: Data, iv: Data, data: Data) -> Data {
    aes(mode: CCMode(kCCModeCTR), key: key, iv: iv, data: data)
  }

  private static func aes(mode: CCMode, key: Data, iv: Data?, data: Data) -> Data {
    guard !data.isEmpty else {
      return Data()
    }

    var cryptor: CCCryptorRef?
    let status = key.withUnsafeBytes { keyBytes in
      withOptionalBytes(iv) { ivBytes in
        CCCryptorCreateWithMode(
          CCOperation(kCCEncrypt),
          mode,
          CCAlgorithm(kCCAlgorithmAES),
          CCPadding(ccNoPadding),
          ivBytes,
          keyBytes.baseAddress,
          key.count,
          nil,
          0,
          0,
          0,
          &cryptor
        )
      }
    }
    guard status == kCCSuccess, let cryptor else {
      fatalError("CCCryptorCreateWithMode failed: \(status)")
    }
    defer { CCCryptorRelease(cryptor) }

    var output = Data(count: data.count)
    var moved = 0
    let updateStatus = output.withUnsafeMutableBytes { outputBytes in
      data.withUnsafeBytes { inputBytes in
        CCCryptorUpdate(
          cryptor,
          inputBytes.baseAddress,
          data.count,
          outputBytes.baseAddress,
          outputBytes.count,
          &moved
        )
      }
    }
    guard updateStatus == kCCSuccess, moved == data.count else {
      fatalError("CCCryptorUpdate failed: \(updateStatus)")
    }
    return output
  }

  private static func withOptionalBytes<R>(_ data: Data?, _ body: (UnsafeRawPointer?) -> R) -> R {
    guard let data else {
      return body(nil)
    }
    return data.withUnsafeBytes { body($0.baseAddress) }
  }

  private static func xor(_ lhs: Data, _ rhs: Data) -> Data {
    Data(zip(lhs, rhs).map { $0 ^ $1 })
  }

  private static func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
    guard lhs.count == rhs.count else {
      return false
    }
    return zip(lhs, rhs).reduce(0) { $0 | ($1.0 ^ $1.1) } == 0
  }
}
