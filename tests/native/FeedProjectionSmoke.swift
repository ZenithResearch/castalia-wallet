import CastaliaWallet
import Foundation

enum Failure: Error { case unavailable, invalidResult }

// Test consumer, not a shipped Wallet host adapter. Executor-confined ownership;
// original raw Data reaches Rust without Foundation JSON conversion.
final class Projection {
  private var handle: UInt64
  init?(source: Data, selection: Data, origin: Data) {
    handle = source.withUnsafeBytes { s in selection.withUnsafeBytes { c in origin.withUnsafeBytes { o in
      castalia_feed_projection_prepare(s.bindMemory(to: UInt8.self).baseAddress, source.count,
        c.bindMemory(to: UInt8.self).baseAddress, selection.count,
        o.bindMemory(to: UInt8.self).baseAddress, origin.count)
    } } }
    if handle == 0 { return nil }
  }
  deinit { castalia_feed_projection_free(handle) }
  func dispose() { castalia_feed_projection_free(handle); handle = 0 }
  func preview() throws -> Data { try result(castalia_feed_projection_preview(handle)) }
  func confirm(source: Data, origin: Data) throws -> Data {
    let consumed = handle
    handle = 0
    return try result(source.withUnsafeBytes { s in origin.withUnsafeBytes { o in
      castalia_feed_projection_confirm(consumed, s.bindMemory(to: UInt8.self).baseAddress, source.count,
        o.bindMemory(to: UInt8.self).baseAddress, origin.count)
    } })
  }
  private func result(_ result: UInt64) throws -> Data {
    guard result != 0 else { throw Failure.unavailable }
    defer { castalia_result_free(result) }
    let size = castalia_result_length(result)
    guard size > 0, size <= 262144 else { throw Failure.invalidResult }
    var output = Data(count: size)
    let copied = output.withUnsafeMutableBytes { castalia_result_copy(result, $0.bindMemory(to: UInt8.self).baseAddress, size) }
    guard copied == size else { throw Failure.invalidResult }
    return output
  }
}

func rejected(_ body: () throws -> Void) {
  do { try body(); preconditionFailure("Expected refusal") } catch { }
}
func equal(_ bytes: Data, _ expected: Any) throws {
  let value = try JSONSerialization.jsonObject(with: bytes) as! NSDictionary
  precondition(value.isEqual(expected), "Selected section differs")
}
func raw(_ c: [String: Any], _ key: String) -> Data { Data((c[key] as! String).utf8) }

func run() throws {
  precondition(castalia_abi_version() == 1 && castalia_feed_projection_abi_version() == 1)
  let fixture = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))) as! [String: Any]
  let cases = fixture["cases"] as! [[String: Any]]
  precondition(cases.count == 46)
  for c in cases {
    let p = Projection(source: raw(c,"sourceRaw"), selection: raw(c,"selectionRaw"), origin: raw(c,"origin"))
    precondition((p != nil) == (c["valid"] as! Bool), c["id"] as! String)
    if let p {
      try equal(p.preview(), c["expectedSection"]!)
      try equal(p.confirm(source: raw(c,"sourceRaw"), origin: raw(c,"origin")), c["expectedSection"]!)
      rejected { _ = try p.preview() }
      rejected { _ = try p.confirm(source: raw(c,"sourceRaw"), origin: raw(c,"origin")) }
    }
  }
  let confirmations = fixture["confirmationCases"] as! [[String: Any]]
  precondition(confirmations.count == 3)
  for c in confirmations {
    let p = Projection(source: raw(c,"sourceRaw"), selection: raw(c,"selectionRaw"), origin: raw(c,"origin"))!
    if c["valid"] as! Bool { _ = try p.confirm(source: raw(c,"currentSourceRaw"), origin: raw(c,"confirmOrigin")) }
    else { rejected { _ = try p.confirm(source: raw(c,"currentSourceRaw"), origin: raw(c,"confirmOrigin")) } }
    rejected { _ = try p.confirm(source: raw(c,"sourceRaw"), origin: raw(c,"origin")) }
  }
  let c = cases[0], source = raw(c,"sourceRaw"), choices = raw(c,"selectionRaw"), origin = raw(c,"origin")
  var mutableSource = source, mutableChoices = choices, mutableOrigin = origin
  let p = Projection(source: mutableSource, selection: mutableChoices, origin: mutableOrigin)!
  mutableSource.resetBytes(in: 0..<mutableSource.count); mutableChoices.resetBytes(in: 0..<mutableChoices.count); mutableOrigin.resetBytes(in: 0..<mutableOrigin.count)
  try equal(p.confirm(source: source, origin: origin), c["expectedSection"]!)
  for bad in [Data(), Data([255]), Data(repeating: 0x20, count: 262145)] {
    precondition(Projection(source: bad, selection: choices, origin: origin) == nil)
    precondition(Projection(source: source, selection: bad, origin: origin) == nil)
    let consumed = Projection(source: source, selection: choices, origin: origin)!
    rejected { _ = try consumed.confirm(source: bad, origin: origin) }
    rejected { _ = try consumed.confirm(source: source, origin: origin) }
  }
  precondition(Projection(source: source, selection: choices, origin: Data([255])) == nil)
  let disposed = Projection(source: source, selection: choices, origin: origin)!
  disposed.dispose(); disposed.dispose()
  rejected { _ = try disposed.preview() }
  var owners: [Projection] = (0..<16).map { _ in Projection(source: source, selection: choices, origin: origin)! }
  precondition(Projection(source: source, selection: choices, origin: origin) == nil)
  owners.removeAll() // deinit releases every owned native preparation.
  let recovered = Projection(source: source, selection: choices, origin: origin)!
  try equal(recovered.confirm(source: source, origin: origin), c["expectedSection"]!)
  print("Swift/C projection: 46 preparation + 3 confirmation vectors, exact data, one-shot failures, byte ownership, bounds, disposal and deinit quota recovery PASS")
}
try run()
