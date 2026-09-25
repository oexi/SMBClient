import XCTest
@testable import SMBClient

final class CryptoTests: XCTestCase {
  func testMD4() async throws {
    XCTAssertEqual(Crypto.md4("".data(using: .utf8)!).hex, "31d6cfe0d16ae931b73c59d7e0c089c0")
    XCTAssertEqual(Crypto.md4("a".data(using: .utf8)!).hex, "bde52cb31de33e46245e05fbdbd6fb24")
    XCTAssertEqual(Crypto.md4("abc".data(using: .utf8)!).hex, "a448017aaf21d8525fc10ae87aa6729d")
    XCTAssertEqual(Crypto.md4("message digest".data(using: .utf8)!).hex, "d9130a8164549fe818874806e1c7014b")
    XCTAssertEqual(Crypto.md4("abcdefghijklmnopqrstuvwxyz".data(using: .utf8)!).hex, "d79e1c308aa5bbcdeea8ed63df412da9")
    XCTAssertEqual(Crypto.md4("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".data(using: .utf8)!).hex, "043f8582f241db351ce627e153e7f0e4")
    XCTAssertEqual(Crypto.md4("12345678901234567890123456789012345678901234567890123456789012345678901234567890".data(using: .utf8)!).hex, "e33b4ddc9c38f2199c3e7b164fcc0536")
    XCTAssertEqual(Crypto.md4("test".data(using: .utf8)!).hex, "db346d691d7acc4dc2625db19f9e3f52")
  }

  func testSHA512() {
    XCTAssertEqual(
      Crypto.sha512(Data("abc".utf8)).hex,
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    )
  }

  func testAESCMAC() {
    let key = Data((0..<16).map { UInt8($0) })
    let expected = [
      0: "97dd6e5a882cbd564c39ae7d1c5a31aa",
      16: "52ae5f5c72c1b60de2ab6e72a8607c1c",
      40: "ec264fb270660e2fc856a709ee7d85cd",
      64: "65949a20621e76e55b90a76b7ce039f4",
      1000: "bd50b6b35ff73bc67104c04dee502f38",
    ]
    for (count, mac) in expected {
      let message = Data((0..<count).map { UInt8(truncatingIfNeeded: $0 * 3) })
      XCTAssertEqual(Crypto.aesCMAC(key: key, data: message).hex, mac, "length \(count)")
    }

    // RFC 4493, Example 2
    XCTAssertEqual(
      Crypto.aesCMAC(key: Data("2b7e151628aed2a6abf7158809cf4f3c")!, data: Data("6bc1bee22e409f96e93d7e117393172a")!).hex,
      "070a16b46b4d4144f79bdd9dd04a287c"
    )
  }

  func testAESCCM() {
    let key = Data((0..<16).map { UInt8($0) })
    let nonce = Data((0xA0..<0xAB).map { UInt8($0) })
    let aad = Data((0x20..<0x40).map { UInt8($0) })
    let expected = [
      0: "4c23dd14d3da03c558bf8f38436aa9af",
      1: "e413840a489dcd84d58e57636c6ba62f03",
      15: "e4bd4a63f2888097e4992dd5bf5dcd7fe715c7920dd2f22108f8f89651b84c",
      16: "e4bd4a63f2888097e4992dd5bf5dcd8ed70ea431938767e41de0dc783b148c92",
      17: "e4bd4a63f2888097e4992dd5bf5dcd8e35725bf489a0689d4356a696ad4dd44678",
      100: "e4bd4a63f2888097e4992dd5bf5dcd8e3506fe6426e80a92c29b79528d5a6022b608c81b4669195f8ef770aec35b0b11e401bf0d9522cfef30194854a59901f793f99545c8dd779bcf00c0aafc20b00d6ba56ddf1ff045da543803f75cd47ff5f795c1f0f7f55bfafeada0999a952875677f9c3b",
    ]
    for (count, sealed) in expected {
      let plaintext = Data((0..<count).map { UInt8(truncatingIfNeeded: $0 * 7) })
      let (ciphertext, tag) = Crypto.aesCCMSeal(key: key, nonce: nonce, plaintext: plaintext, aad: aad)
      XCTAssertEqual((ciphertext + tag).hex, sealed, "length \(count)")
      XCTAssertEqual(Crypto.aesCCMOpen(key: key, nonce: nonce, ciphertext: ciphertext, tag: tag, aad: aad), plaintext)

      var tampered = tag
      tampered[0] ^= 0x01
      XCTAssertNil(Crypto.aesCCMOpen(key: key, nonce: nonce, ciphertext: ciphertext, tag: tampered, aad: aad))
    }

    let key256 = Data((0..<32).map { UInt8($0) })
    let plaintext = Data("The quick brown fox jumps over the lazy dog".utf8)
    let (ciphertext, tag) = Crypto.aesCCMSeal(key: key256, nonce: nonce, plaintext: plaintext, aad: aad)
    XCTAssertEqual(
      (ciphertext + tag).hex,
      "ccc926af80279d2d83db57805992dac9aca326f9f344ff2081ab225b244b050039520e72014008ef338fb6fc51e68e62a4ff8cc3eb6a36d515ee1c"
    )
  }

  func testAESGCM() throws {
    let key256 = Data((0..<32).map { UInt8($0) })
    let nonce = Data((0xB0..<0xBC).map { UInt8($0) })
    let aad = Data((0x20..<0x40).map { UInt8($0) })
    let plaintext = Data("The quick brown fox jumps over the lazy dog".utf8)

    let (ciphertext, tag) = try Crypto.aesGCMSeal(key: key256, nonce: nonce, plaintext: plaintext, aad: aad)
    XCTAssertEqual(
      (ciphertext + tag).hex,
      "cd3d3f8b9db8d23c2cd8f5d0a22ae6e2e25331f27f5be2452deeed8739f0d2626d2e035602a4df98c134c7e635ac08b7759136acbcc4b4c28864f2"
    )
    XCTAssertEqual(Crypto.aesGCMOpen(key: key256, nonce: nonce, ciphertext: ciphertext, tag: tag, aad: aad), plaintext)

    let key = Data((0..<16).map { UInt8($0) })
    XCTAssertEqual(try Crypto.aesGMAC(key: key, nonce: nonce, data: plaintext).hex, "11037943d7ef535f379f646a9ae57255")
  }

  func testKDF() {
    let sessionKey = Data("270E1BA896585EEB7AF3472D3B4C75A7")!
    XCTAssertEqual(
      Crypto.kdf(key: sessionKey, label: Data("SMB2AESCMAC\0".utf8), context: Data("SmbSign\0".utf8), length: 16).hex,
      "4eeaf9e6bc024e1adf4a560f01570deb"
    )
    XCTAssertEqual(
      Crypto.kdf(key: sessionKey, label: Data("SMBC2SCipherKey\0".utf8), context: Data((0..<64).map { UInt8($0) }), length: 32).hex,
      "c273f0de35671e766ef5106b605054d70385f9237f1327662763de8ac2444317"
    )
  }

  func testMessageCipherRoundTrip() throws {
    for cipher in [Negotiate.Cipher.aes128CCM, .aes128GCM, .aes256CCM, .aes256GCM] {
      let clientKey = Crypto.randomBytes(count: cipher.keyLength)
      let serverKey = Crypto.randomBytes(count: cipher.keyLength)
      let client = MessageCipher(cipher: cipher, sessionId: 0x1234, encryptionKey: clientKey, decryptionKey: serverKey)
      let server = MessageCipher(cipher: cipher, sessionId: 0x1234, encryptionKey: serverKey, decryptionKey: clientKey)

      let message = Data((0..<1000).map { UInt8(truncatingIfNeeded: $0) })
      let encrypted = try client.encrypt(message)
      XCTAssertTrue(TransformHeader.isTransformMessage(encrypted))
      XCTAssertEqual(encrypted.count, TransformHeader.size + message.count)
      XCTAssertEqual(try server.decrypt(encrypted), message)

      var tampered = encrypted
      tampered[TransformHeader.size + 10] ^= 0xFF
      XCTAssertThrowsError(try server.decrypt(tampered))
    }
  }
}
