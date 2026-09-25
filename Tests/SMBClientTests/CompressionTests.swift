import XCTest
@testable import SMBClient

final class CompressionTests: XCTestCase {
  func testLZ77DecompressSpecExamples() throws {
    // MS-XCA 3.1 examples.
    let literals = Data("3f000000")! + Data("abcdefghijklmnopqrstuvwxyz".utf8)
    XCTAssertEqual(try LZ77.decompress(literals, expectedSize: 26), Data("abcdefghijklmnopqrstuvwxyz".utf8))

    let repeated = Data("ffffff1f61626317000fff2601")!
    XCTAssertEqual(
      try LZ77.decompress(repeated, expectedSize: 300),
      Data(String(repeating: "abc", count: 100).utf8)
    )
  }

  func testLZ77CompressMatchesSpecExample() {
    XCTAssertEqual(
      LZ77.compress(Data(String(repeating: "abc", count: 100).utf8)).hex,
      "ffffff1f61626317000fff2601"
    )
  }

  func testLZ77RoundTrip() throws {
    var inputs: [Data] = [
      Data(),
      Data([0x41]),
      Data(count: 1_000_000),
      Data((0..<70_000).map { UInt8(truncatingIfNeeded: $0 / 7) }),
      Data((0..<5_000).map { _ in UInt8.random(in: 0...255) }),
    ]
    for _ in 0..<50 {
      let alphabet = UInt8.random(in: 1...255)
      inputs.append(Data((0..<Int.random(in: 0...20_000)).map { _ in UInt8.random(in: 0...alphabet) }))
    }

    for input in inputs {
      let compressed = LZ77.compress(input)
      XCTAssertEqual(try LZ77.decompress(compressed, expectedSize: input.count), input)
    }
  }

  func testLZ77RejectsCorruptInput() {
    // A match pointing before the start of the output.
    XCTAssertThrowsError(try LZ77.decompress(Data("000000800000")!, expectedSize: 10))
  }

  func testMessageCompressorRoundTrip() throws {
    let compressor = MessageCompressor(algorithms: [.lz77])
    let message = Header(command: .write, messageId: 1, sessionId: 2).encoded()
      + Data(String(repeating: "SMB compression ", count: 1000).utf8)

    let compressed = try XCTUnwrap(compressor.compress(message, uncompressedPrefix: 64))
    XCTAssertTrue(CompressionTransformHeader.isCompressedMessage(compressed))
    XCTAssertLessThan(compressed.count, message.count)
    XCTAssertEqual(compressed[CompressionTransformHeader.size..<(CompressionTransformHeader.size + 64)], message.prefix(64))
    XCTAssertEqual(try compressor.decompress(compressed), message)

    // Incompressible or small messages are left alone.
    XCTAssertNil(compressor.compress(Data((0..<10_000).map { _ in UInt8.random(in: 0...255) })))
    XCTAssertNil(compressor.compress(Data(count: 100)))
  }

  func testCompressionContextEncoding() {
    let context = Negotiate.CompressionCapabilities(compressionAlgorithms: [.lz77]).context
    XCTAssertEqual(context.contextType, Negotiate.NegotiateContextType.compressionCapabilities.rawValue)
    XCTAssertEqual(context.data.hex, "01000000000000000200")

    let parsed = Negotiate.CompressionCapabilities(context: context)
    XCTAssertEqual(parsed?.compressionAlgorithms, [.lz77])
  }
}
