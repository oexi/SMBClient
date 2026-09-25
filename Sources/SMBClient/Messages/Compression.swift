import Foundation

/// SMB2 COMPRESSION_TRANSFORM_HEADER, unchained form (MS-SMB2 2.2.42.1).
public struct CompressionTransformHeader {
  public static let protocolId: UInt32 = 0x424D53FC
  public static let size = 16

  public let originalCompressedSegmentSize: UInt32
  public let compressionAlgorithm: UInt16
  public let flags: UInt16
  public let offset: UInt32

  init(originalCompressedSegmentSize: UInt32, compressionAlgorithm: Negotiate.CompressionAlgorithm, offset: UInt32) {
    self.originalCompressedSegmentSize = originalCompressedSegmentSize
    self.compressionAlgorithm = compressionAlgorithm.rawValue
    self.flags = 0
    self.offset = offset
  }

  init(data: Data) {
    let reader = ByteReader(data)
    let _: UInt32 = reader.read()
    originalCompressedSegmentSize = reader.read()
    compressionAlgorithm = reader.read()
    flags = reader.read()
    offset = reader.read()
  }

  func encoded() -> Data {
    var data = Data()
    data += CompressionTransformHeader.protocolId
    data += originalCompressedSegmentSize
    data += compressionAlgorithm
    data += flags
    data += offset
    return data
  }

  static func isCompressedMessage(_ data: Data) -> Bool {
    guard data.count >= 4 else {
      return false
    }
    return data.prefix(4).elementsEqual([0xFC, 0x53, 0x4D, 0x42])
  }
}

/// Compresses and decompresses messages for an SMB 3.1.1 connection that
/// negotiated compression (MS-SMB2 3.1.4.4, 3.2.5.1.10).
final class MessageCompressor {
  /// Messages smaller than this are sent uncompressed, as Windows does.
  static let minimumMessageSize = 4096

  let algorithms: [Negotiate.CompressionAlgorithm]

  init(algorithms: [Negotiate.CompressionAlgorithm]) {
    self.algorithms = algorithms
  }

  /// Compresses `message`, leaving the first `uncompressedPrefix` bytes as is.
  /// Returns nil when compression is not worthwhile.
  func compress(_ message: Data, uncompressedPrefix: Int = 0) -> Data? {
    guard message.count >= MessageCompressor.minimumMessageSize, algorithms.contains(.lz77) else {
      return nil
    }

    let prefix = message.prefix(uncompressedPrefix)
    let compressed = LZ77.compress(Data(message.dropFirst(uncompressedPrefix)))
    guard CompressionTransformHeader.size + prefix.count + compressed.count < message.count else {
      return nil
    }

    let header = CompressionTransformHeader(
      originalCompressedSegmentSize: UInt32(truncatingIfNeeded: message.count - prefix.count),
      compressionAlgorithm: .lz77,
      offset: UInt32(truncatingIfNeeded: prefix.count)
    )
    return header.encoded() + prefix + compressed
  }

  func decompress(_ message: Data) throws -> Data {
    guard message.count >= CompressionTransformHeader.size else {
      throw CompressionError.malformedMessage
    }
    let header = CompressionTransformHeader(data: Data(message.prefix(CompressionTransformHeader.size)))
    let body = Data(message.dropFirst(CompressionTransformHeader.size))

    guard header.flags == 0, Int(header.offset) <= body.count else {
      throw CompressionError.malformedMessage
    }
    let prefix = body.prefix(Int(header.offset))
    let compressed = Data(body.dropFirst(Int(header.offset)))
    let expectedSize = Int(header.originalCompressedSegmentSize)

    let decompressed: Data
    switch Negotiate.CompressionAlgorithm(rawValue: header.compressionAlgorithm) {
    case .noCompression?:
      decompressed = compressed
    case .lz77?:
      decompressed = try LZ77.decompress(compressed, expectedSize: expectedSize)
    default:
      throw CompressionError.unsupportedAlgorithm(header.compressionAlgorithm)
    }

    guard decompressed.count == expectedSize else {
      throw CompressionError.malformedMessage
    }
    return prefix + decompressed
  }
}

public enum CompressionError: Error {
  case malformedMessage
  case unsupportedAlgorithm(UInt16)
}

/// Plain LZ77 (LZXpress) as specified in MS-XCA 2.3 and 2.4.
enum LZ77 {
  private static let maxOffset = 8192
  private static let hashBits = 15
  private static let maxChainDepth = 16

  static func decompress(_ input: Data, expectedSize: Int) throws -> Data {
    let input = [UInt8](input)
    var output = [UInt8]()
    output.reserveCapacity(expectedSize)

    var inputPosition = 0
    var bufferedFlags: UInt32 = 0
    var bufferedFlagCount = 0
    var lastLengthHalfByte = 0

    func readUInt16() throws -> Int {
      guard inputPosition + 2 <= input.count else { throw CompressionError.malformedMessage }
      defer { inputPosition += 2 }
      return Int(input[inputPosition]) | Int(input[inputPosition + 1]) << 8
    }

    func readUInt32() throws -> Int {
      guard inputPosition + 4 <= input.count else { throw CompressionError.malformedMessage }
      defer { inputPosition += 4 }
      return Int(input[inputPosition])
        | Int(input[inputPosition + 1]) << 8
        | Int(input[inputPosition + 2]) << 16
        | Int(input[inputPosition + 3]) << 24
    }

    func readByte() throws -> Int {
      guard inputPosition < input.count else { throw CompressionError.malformedMessage }
      defer { inputPosition += 1 }
      return Int(input[inputPosition])
    }

    while output.count < expectedSize {
      if bufferedFlagCount == 0 {
        if inputPosition == input.count { break }
        bufferedFlags = UInt32(try readUInt32())
        bufferedFlagCount = 32
      }
      bufferedFlagCount -= 1

      if bufferedFlags & (1 << UInt32(bufferedFlagCount)) == 0 {
        output.append(UInt8(try readByte()))
        continue
      }

      if inputPosition == input.count { break }

      let matchBytes = try readUInt16()
      var matchLength = matchBytes % 8
      let matchOffset = matchBytes / 8 + 1

      if matchLength == 7 {
        if lastLengthHalfByte == 0 {
          guard inputPosition < input.count else { throw CompressionError.malformedMessage }
          matchLength = Int(input[inputPosition]) % 16
          lastLengthHalfByte = inputPosition
          inputPosition += 1
        } else {
          matchLength = Int(input[lastLengthHalfByte]) / 16
          lastLengthHalfByte = 0
        }
        if matchLength == 15 {
          matchLength = try readByte()
          if matchLength == 255 {
            matchLength = try readUInt16()
            if matchLength == 0 {
              matchLength = try readUInt32()
            }
            guard matchLength >= 15 + 7 else { throw CompressionError.malformedMessage }
            matchLength -= 15 + 7
          }
          matchLength += 15
        }
        matchLength += 7
      }
      matchLength += 3

      guard matchOffset <= output.count, output.count + matchLength <= expectedSize else {
        throw CompressionError.malformedMessage
      }
      let start = output.count - matchOffset
      for i in 0..<matchLength {
        output.append(output[start + i])
      }
    }

    return Data(output)
  }

  static func compress(_ input: Data) -> Data {
    let input = [UInt8](input)
    var output = [UInt8](repeating: 0, count: 4)
    output.reserveCapacity(input.count + input.count / 8 + 8)

    var flags: UInt32 = 0
    var flagCount = 0
    var flagOutputPosition = 0
    var lastLengthHalfByte = 0

    let hashSize = 1 << hashBits
    var head = [Int32](repeating: -1, count: hashSize)
    var previous = [Int32](repeating: -1, count: input.count)

    func hash(_ position: Int) -> Int {
      let value = Int(input[position]) | Int(input[position + 1]) << 8 | Int(input[position + 2]) << 16
      return (value &* 0x9E3779B1) >> (32 - hashBits) & (hashSize - 1)
    }

    func insert(_ position: Int) {
      guard position + 3 <= input.count else { return }
      let h = hash(position)
      previous[position] = head[h]
      head[h] = Int32(position)
    }

    func appendUInt16(_ value: Int) {
      output.append(UInt8(truncatingIfNeeded: value))
      output.append(UInt8(truncatingIfNeeded: value >> 8))
    }

    func appendUInt32(_ value: Int) {
      appendUInt16(value)
      appendUInt16(value >> 16)
    }

    func writeFlags() {
      output[flagOutputPosition] = UInt8(truncatingIfNeeded: flags)
      output[flagOutputPosition + 1] = UInt8(truncatingIfNeeded: flags >> 8)
      output[flagOutputPosition + 2] = UInt8(truncatingIfNeeded: flags >> 16)
      output[flagOutputPosition + 3] = UInt8(truncatingIfNeeded: flags >> 24)
    }

    var position = 0
    while position < input.count {
      var bestLength = 0
      var bestOffset = 0

      if position + 3 <= input.count {
        var candidate = Int(head[hash(position)])
        var depth = 0
        while candidate >= 0, position - candidate <= maxOffset, depth < maxChainDepth {
          var length = 0
          while position + length < input.count, input[candidate + length] == input[position + length] {
            length += 1
          }
          if length > bestLength {
            bestLength = length
            bestOffset = position - candidate
            if position + length == input.count { break }
          }
          candidate = Int(previous[candidate])
          depth += 1
        }
      }

      if bestLength < 3 {
        output.append(input[position])
        insert(position)
        position += 1
        flags <<= 1
      } else {
        var matchLength = bestLength - 3
        let encodedOffset = (bestOffset - 1) << 3

        if matchLength < 7 {
          appendUInt16(encodedOffset + matchLength)
        } else {
          appendUInt16(encodedOffset + 7)
          matchLength -= 7

          var needsExtraLength = false
          if lastLengthHalfByte == 0 {
            lastLengthHalfByte = output.count
            output.append(UInt8(min(matchLength, 15)))
          } else {
            output[lastLengthHalfByte] |= UInt8(min(matchLength, 15)) << 4
            lastLengthHalfByte = 0
          }
          needsExtraLength = matchLength >= 15

          if needsExtraLength {
            matchLength -= 15
            if matchLength < 255 {
              output.append(UInt8(matchLength))
            } else {
              output.append(255)
              matchLength += 7 + 15
              if matchLength < 1 << 16 {
                appendUInt16(matchLength)
              } else {
                appendUInt16(0)
                appendUInt32(matchLength)
              }
            }
          }
        }

        for i in 0..<bestLength {
          insert(position + i)
        }
        position += bestLength
        flags = (flags << 1) | 1
      }

      flagCount += 1
      if flagCount == 32 {
        writeFlags()
        flagCount = 0
        flagOutputPosition = output.count
        output.append(contentsOf: [0, 0, 0, 0])
      }
    }

    if flagCount == 0 {
      flags = 0xFFFF_FFFF
    } else {
      flags <<= UInt32(32 - flagCount)
      flags |= (UInt32(1) << UInt32(32 - flagCount)) &- 1
    }
    writeFlags()

    return Data(output)
  }
}
