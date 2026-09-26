import Foundation
import Network

public class Connection {
  let host: String
  var onDisconnected: (Error) -> Void

  private let connection: NWConnection
  private let queue: DispatchQueue
  private var buffer = Data()

  private let semaphore = Semaphore(value: 1)

  /// Set once an SMB 3.x session is established, so encrypted responses
  /// (TRANSFORM_HEADER) can be decrypted before they are parsed.
  var messageCipher: MessageCipher?
  /// Set when SMB 3.1.1 compression was negotiated.
  var messageCompressor: MessageCompressor?

  public var state: NWConnection.State {
    connection.state
  }

  /// The numeric address the connection reached, once connected.
  public var remoteAddress: String? {
    guard case let .hostPort(host, _)? = connection.currentPath?.remoteEndpoint else {
      return nil
    }
    switch host {
    case .ipv4(let address):
      return "\(address)"
    case .ipv6(let address):
      return "\(address)"
    case .name(let name, _):
      return name
    @unknown default:
      return nil
    }
  }

  public enum Transport {
    case tcp
    /// SMB over QUIC (MS-SMB2 2.1): TLS 1.3 with ALPN "smb", usually on UDP
    /// port 443. Requires macOS 12, iOS 15 or later.
    case quic
  }

  public let transport: Transport
  public let port: Int

  public convenience init(host: String) {
    self.init(host: host, port: 445)
  }

  public init(host: String, port: Int, transport: Transport = .tcp) {
    self.host = host
    self.port = port
    self.transport = transport

    let endpoint = NWEndpoint.hostPort(
      host: NWEndpoint.Host(host),
      port: NWEndpoint.Port(rawValue: UInt16(port))!
    )
    connection = NWConnection(to: endpoint, using: Connection.parameters(for: transport))
    queue = DispatchQueue(label: "com.kishikawakatsumi.smbclient.connection.\(host):\(port)", qos: .userInitiated)
    onDisconnected = { _ in }
  }

  private static func parameters(for transport: Transport) -> NWParameters {
    switch transport {
    case .tcp:
      return .tcp
    case .quic:
      guard #available(macOS 12.0, iOS 15.0, *) else {
        preconditionFailure("SMB over QUIC requires macOS 12, iOS 15 or later")
      }
      let options = NWProtocolQUIC.Options(alpn: ["smb"])
      options.direction = .bidirectional
      return NWParameters(quic: options)
    }
  }

  public func connect() async throws {
    return try await withCheckedThrowingContinuation { (continuation) in
      connection.stateUpdateHandler = { [weak self] (state) in
        switch state {
        case .setup, .preparing:
          break
        case .waiting(let error):
          continuation.resume(throwing: error)
          self?.connection.stateUpdateHandler = nil
        case .ready:
          continuation.resume()
          // NWConnection delivers all state updates on `queue`, so assigning
          // stateUpdateHandler here is safe: it runs on the same serial queue
          // as any future state updates.
          self?.connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .waiting(let error), .failed(let error):
              self?.onDisconnected(error)
            case .setup, .preparing, .ready, .cancelled:
              break
            @unknown default:
              break
            }
          }
        case .failed(let error):
          continuation.resume(throwing: error)
          self?.connection.stateUpdateHandler = nil
        case .cancelled:
          continuation.resume(throwing: ConnectionError.cancelled)
          self?.connection.stateUpdateHandler = nil
        @unknown default:
          break
        }
      }

      connection.start(queue: queue)
    }
  }

  public func disconnect() {
    // Do not nil stateUpdateHandler before cancelling: NWConnection delivers
    // the .cancelled state update asynchronously, and clearing the handler
    // first would prevent any in-flight connect() continuation from being
    // resumed, causing a hang. The retain cycle is instead broken by
    // capturing self weakly in the handler closures.
    connection.cancel()
  }

  struct Response {
    /// Each response message exactly as the server sent it (after removing
    /// encryption and compression), so its signature can be verified.
    var messages: [Data]
    /// Whether every frame of the response arrived encrypted.
    var encrypted: Bool

    func check() throws {
      if let failure = messages.first(where: { !Connection.isSuccess($0) }) {
        throw ErrorResponse(data: failure)
      }
    }
  }

  /// Sends a message (or a compound chain) and returns the response bytes,
  /// concatenated in order.
  public func send(_ data: Data) async throws -> Data {
    let response = try await exchange(data)
    try response.check()
    return response.messages.reduce(Data(), +)
  }

  /// Sends a message (or a compound chain) and returns each response message
  /// separately. Interim STATUS_PENDING responses are replaced by the final
  /// response with the same MessageId. Error statuses are not thrown here.
  func exchange(_ data: Data) async throws -> Response {
    try await exchange { data }
  }

  /// Like `exchange(_:)`, but builds the packet only once this exchange holds
  /// the connection, so anything `prepare` assigns (message IDs) follows
  /// the order in which packets are actually sent.
  func exchange(_ prepare: () throws -> Data) async throws -> Response {
    await semaphore.wait()
    defer { Task { await semaphore.signal() } }

    switch connection.state {
    case .setup:
      try await connect()
    case .waiting(let error), .failed(let error):
      onDisconnected(error)
      throw error
    case .preparing, .ready:
      break
    case .cancelled:
      throw ConnectionError.cancelled
    @unknown default:
      throw ConnectionError.unknown
    }

    let transportPacket = DirectTCPPacket(smb2Message: try prepare())
    try await sendRaw(transportPacket.encoded())

    var (messages, encrypted) = try await receiveMessages()
    while let index = messages.firstIndex(where: { Connection.isInterim($0) }) {
      let messageId = Header(data: messages[index]).messageId
      var replaced = false
      while !replaced {
        let (next, nextEncrypted) = try await receiveMessages()
        for message in next where Header(data: message).messageId == messageId {
          messages[index] = message
          encrypted = encrypted && nextEncrypted
          replaced = true
        }
      }
    }

    return Response(messages: messages, encrypted: encrypted)
  }

  private func sendRaw(_ content: Data) async throws {
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
      connection.send(content: content, completion: .contentProcessed { error in
        if let error {
          continuation.resume(throwing: error)
        } else {
          continuation.resume()
        }
      })
    }
  }

  /// Receives one transport frame and splits it into its SMB2 messages.
  /// Unsolicited oplock/lease break notifications are skipped.
  private func receiveMessages() async throws -> (messages: [Data], encrypted: Bool) {
    while true {
      let frame = try await receiveFrame()
      let encrypted = TransformHeader.isTransformMessage(frame)
      let messages = Connection.split(try decode(frame))
      guard !messages.isEmpty else {
        throw ConnectionError.unknown
      }
      if messages.count == 1, Header(data: messages[0]).messageId == UInt64.max {
        continue
      }
      return (messages, encrypted)
    }
  }

  private func receiveFrame() async throws -> Data {
    try await fill(upTo: 4)
    let length = Int(DirectTCPPacket(response: Data(buffer.prefix(4))).protocolLength)
    try await fill(upTo: 4 + length)

    let frame = Data(buffer[(buffer.startIndex + 4)..<(buffer.startIndex + 4 + length)])
    buffer = Data(buffer.dropFirst(4 + length))
    return frame
  }

  private func fill(upTo byteCount: Int) async throws {
    while buffer.count < byteCount {
      buffer.append(try await receiveChunk())
    }
  }

  private func receiveChunk() async throws -> Data {
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
      connection.receive(minimumIncompleteLength: 1, maximumLength: 1 << 20) { (content, _, isComplete, error) in
        if let error {
          continuation.resume(throwing: error)
        } else if let content, !content.isEmpty {
          continuation.resume(returning: content)
        } else if isComplete {
          continuation.resume(throwing: ConnectionError.disconnected)
        } else {
          continuation.resume(returning: Data())
        }
      }
    }
  }

  /// Removes encryption and compression transforms (MS-SMB2 3.2.5.1.1.1).
  private func decode(_ frame: Data) throws -> Data {
    var data = frame
    if TransformHeader.isTransformMessage(data) {
      guard let messageCipher else {
        throw MessageCipherError.encryptionNotSupported
      }
      data = try messageCipher.decrypt(data)
    }
    if CompressionTransformHeader.isCompressedMessage(data) {
      guard let messageCompressor else {
        throw CompressionError.malformedMessage
      }
      data = try messageCompressor.decompress(data)
    }
    return data
  }

  /// Splits a compound response into its messages. Each message except the
  /// last spans NextCommand bytes, including padding, which is what its
  /// signature covers.
  static func split(_ frame: Data) -> [Data] {
    var messages = [Data]()
    var offset = frame.startIndex
    while frame.endIndex - offset >= 64 {
      let header = Header(data: Data(frame[offset..<(offset + 64)]))
      let next = Int(header.nextCommand)
      if next == 0 || offset + next > frame.endIndex {
        messages.append(Data(frame[offset...]))
        break
      }
      messages.append(Data(frame[offset..<(offset + next)]))
      offset += next
    }
    return messages
  }

  private static func isInterim(_ message: Data) -> Bool {
    NTStatus(Header(data: message).status) == .pending
  }

  static func isSuccess(_ message: Data) -> Bool {
    switch NTStatus(Header(data: message).status) {
    case .success, .moreProcessingRequired, .noMoreFiles, .endOfFile:
      return true
    default:
      return false
    }
  }
}

public enum ConnectionError: Error {
  case disconnected
  case cancelled
  case unknown
}
