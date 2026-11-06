import Foundation

// Only the trusted host calls this bridge. Mesh owns the proof decision and
// the SDK owns custody; neither address nor derivation index comes from JS.
enum MeshMessengerBountyBridge {
  typealias Mesh = (String, Data) throws -> Data
  typealias SDK = (UInt32, Data) throws -> Data
  static func packet(_ fields: [Data]) -> Data {
    var output = Data()
    func u32(_ n: Int) -> Data { Data([UInt8(truncatingIfNeeded:n >> 24), UInt8(truncatingIfNeeded:n >> 16), UInt8(truncatingIfNeeded:n >> 8), UInt8(truncatingIfNeeded:n)]) }
    output.append(u32(fields.count))
    for field in fields { output.append(u32(field.count)); output.append(field) }
    return output
  }
  private struct State { let enabled: Bool; let status: UInt8; let proof: Data }
  private static func view(_ data: Data) throws -> State {
    guard data.count<=160 else {throw Failure.invalid}
    var at=0
    func u32() throws -> Int {guard at+4<=data.count else {throw Failure.invalid};let n=data[at..<at+4].reduce(0){($0<<8)|Int($1)};at+=4;return n}
    guard try u32()==6 else {throw Failure.invalid}
    var fields:[Data]=[]
    for _ in 0..<6 {let count=try u32();guard count<=data.count-at else {throw Failure.invalid};fields.append(data.subdata(in:at..<at+count));at+=count}
    guard at==data.count, fields[0]==Data([1,66,70,80]), fields[1].count==1, fields[1][0]<=1, fields[2].count==1, fields[2][0]<=5, fields[5].count==8 else {throw Failure.invalid}
    let status=fields[2][0], index=fields[5].reduce(UInt64(0)){($0<<8)|UInt64($1)}
    guard (status==0 ? fields[3].isEmpty : fields[3].count==32), (status<2 ? fields[4].isEmpty : fields[4].count==32),
      (status==3 ? index<2147483648 && fields[4].contains(where:{$0 != 0}) : index==0),
      (!(status==2 || status==4) || fields[4].allSatisfy({$0==0})) else {throw Failure.invalid}
    return State(enabled:fields[1][0]==1,status:status,proof:fields[3])
  }
  static func preflight(_ database: Data, mesh: Mesh, sdk: SDK) throws {
    for _ in 0..<3 {
      let state=try view(mesh("mesh_messenger_bounty_status",database))
      if state.status != 1 {return}
      let symbol:String, request:Data
      switch Result(catching:{try sdk(4,Data())}) {
      case .success(let reservation):
        guard reservation.count==40 else {throw Failure.invalid}
        symbol="mesh_messenger_bounty_commit";request=packet([database,state.proof,reservation])
      case .failure:
        symbol="mesh_messenger_bounty_unavailable";request=packet([database,state.proof])
      }
      let response:Data
      do {response=try mesh(symbol,request)} catch {continue}
      guard try view(response).status != 1 else {throw Failure.invalid}
      return
    }
    guard try view(mesh("mesh_messenger_bounty_status",database)).status != 1 else {throw Failure.pending}
  }
  static func setEnabled(_ database: Data, _ flag: UInt8, mesh: Mesh, sdk: SDK) throws -> Data {
    guard flag<=1 else {throw Failure.invalid}
    if flag==1 {let address=try sdk(2,Data());guard address.count==32 && address.contains(where:{$0 != 0}) else {throw Failure.invalid}}
    let output=try mesh("mesh_messenger_bounty_set_enabled",packet([database,Data([flag])]))
    guard try view(output).enabled == (flag==1) else {throw Failure.invalid}
    return output
  }
  static func invokeProof(_ symbol:String, _ database:Data, mesh:Mesh, sdk:SDK) throws -> Data {
    guard symbol=="mesh_messenger_transparency_fork" || symbol=="mesh_messenger_fork_filing" else {throw Failure.invalid}
    for _ in 0..<3 {
      try preflight(database,mesh:mesh,sdk:sdk)
      do {return try mesh(symbol,database)} catch {if !error.localizedDescription.contains("bounty_selection_pending") {throw error}}
    }
    throw Failure.pending
  }
  private static func fields(_ input:Data, count:Int, maximum:Int) throws -> [Data] {
    guard input.count<=maximum else {throw Failure.invalid}
    var at=0
    func u32() throws -> Int {
      guard at+4<=input.count else {throw Failure.invalid}
      let n=input[at..<at+4].reduce(0){($0<<8)|Int($1)};at+=4;return n
    }
    guard try u32()==count else {throw Failure.invalid}
    var result:[Data]=[]
    for _ in 0..<count {
      let n=try u32();guard n<=input.count-at else {throw Failure.invalid}
      result.append(input.subdata(in:at..<at+n));at+=n
    }
    guard at==input.count else {throw Failure.invalid};return result
  }
  private static func movementResult(_ input:Data, identity:Data, destination:Data) throws -> UInt8 {
    let f=try fields(input,count:12,maximum:2048)
    guard f[0]==Data([1,66,77,87]), f[1]==identity, f[2].count==1, f[2][0]<=5,
      f[4].count==32, f[5]==destination, f[6].count==32, f[7].count==8,
      f[8].count==1, f[8][0]<=18, f[9].count==8, f[10].count==8, f[11].count<=256,
      String(data:f[11],encoding:.utf8) != nil,
      (f[2][0]<2 ? f[3].isEmpty : f[3].count==64) else {throw Failure.invalid}
    return f[2][0]
  }
  static func movement(_ input:Data, database:Data, mesh:Mesh, sdk:SDK) throws -> Data {
    let request=try fields(input,count:2,maximum:8192)
    guard request[0]==database, request[1].count==32, request[1].contains(where:{$0 != 0}) else {throw Failure.invalid}
    let payer=try sdk(2,Data())
    guard payer.count==32, payer.contains(where:{$0 != 0}) else {throw Failure.invalid}
    let raw=try mesh("mesh_messenger_bounty_transfer_prepare",packet([database,request[1],payer]))
    let p=try fields(raw,count:6,maximum:512)
    guard p[0]==Data([1,66,77,80]), p[1].count==32, p[1].contains(where:{$0 != 0}),
      p[2].count==1,p[3].count==166,p[3].prefix(4)==Data([1,66,87,84]),p[3].subdata(in:44..<76)==request[1],
      p[5].count==1,(1...5).contains(p[5][0]),p[2][0]==(p[5][0]==1 ? 1:0),
      (p[5][0]<2 ? p[4].isEmpty : p[4].count==64) else {throw Failure.invalid}
    let identity=p[1]
    if p[2][0]==1 {
      let wire=try sdk(5,p[3]);guard !wire.isEmpty,wire.count<=1232 else {throw Failure.invalid}
      let committed=try mesh("mesh_messenger_bounty_transfer_commit",packet([database,identity,wire]))
      let status=try movementResult(committed,identity:identity,destination:request[1])
      if status>=4 {return committed};guard status>=2 else {throw Failure.invalid}
    } else if p[5][0]>=4 {
      let output=try mesh("mesh_messenger_bounty_transfer_status",database)
      _=try movementResult(output,identity:identity,destination:request[1]);return output
    }
    let output=try mesh("mesh_messenger_bounty_transfer_submit",packet([database,identity]))
    guard try movementResult(output,identity:identity,destination:request[1])>=2 else {throw Failure.invalid}
    return output
  }

  enum Failure: Error { case invalid, pending }
}
