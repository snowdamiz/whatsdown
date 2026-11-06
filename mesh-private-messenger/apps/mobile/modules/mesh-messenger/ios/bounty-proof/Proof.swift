import Foundation
@main enum Proof {
  static func view(_ status: UInt8, enabled: Bool = true) -> Data {
    MeshMessengerBountyBridge.packet([Data([1,66,70,80]),Data([enabled ? 1:0]),Data([status]), status==0 ? Data() : Data(repeating:7,count:32), status<2 ? Data() : Data(repeating:status==2 || status==4 ? 0:8,count:32), Data(repeating:0,count:8)])
  }
  static func main() throws {
    let db=Data("/db".utf8); var calls=0
    for status: UInt8 in [0,2,3,4,5] { try MeshMessengerBountyBridge.preflight(db,mesh:{name,input in precondition(name.hasSuffix("_status") && input==db);return view(status)},sdk:{_,_ in fatalError("terminal proof reached SDK")}) }
    let raw=Data(repeating:0,count:8)+Data(repeating:9,count:32)
    try MeshMessengerBountyBridge.preflight(db,mesh:{name,input in
      if name.hasSuffix("_status") {return view(1)}
      precondition(name.hasSuffix("_commit") && input==MeshMessengerBountyBridge.packet([db,Data(repeating:7,count:32),raw]));return view(3)
    },sdk:{op,input in precondition(op==4 && input.isEmpty);calls+=1;return raw})
    precondition(calls==1)
    try MeshMessengerBountyBridge.preflight(db,mesh:{name,input in
      if name.hasSuffix("_status") {return view(1)}
      precondition(name.hasSuffix("_unavailable") && input==MeshMessengerBountyBridge.packet([db,Data(repeating:7,count:32)]));return view(4)
    },sdk:{_,_ in throw NSError(domain:"wallet",code:3)})
    var reads=0; calls=0
    try MeshMessengerBountyBridge.preflight(db,mesh:{name,_ in
      if name.hasSuffix("_status") {reads+=1;return view(reads==1 ? 1:3)}
      precondition(name.hasSuffix("_commit"));throw NSError(domain:"race",code:1)
    },sdk:{_,_ in calls+=1;return raw})
    precondition(calls==1)
    let disabled=try MeshMessengerBountyBridge.setEnabled(db,0,mesh:{name,input in precondition(name.hasSuffix("_set_enabled") && input==MeshMessengerBountyBridge.packet([db,Data([0])]));return view(0,enabled:false)},sdk:{_,_ in fatalError("disable needs no wallet")})
    precondition(disabled==view(0,enabled:false))
    do { _=try MeshMessengerBountyBridge.setEnabled(db,1,mesh:{_,_ in fatalError("SDK failure changed preference")},sdk:{op,_ in precondition(op==2);throw NSError(domain:"wallet",code:3)});fatalError("enable accepted missing custody") } catch {}
    do {try MeshMessengerBountyBridge.preflight(db,mesh:{_,_ in view(1)+Data([0])},sdk:{_,_ in fatalError("malformed view reached SDK")});fatalError("malformed view accepted")} catch {}
    for symbol in ["mesh_messenger_transparency_fork","mesh_messenger_fork_filing"] {
      var published=0;var committed=false
      let output=try MeshMessengerBountyBridge.invokeProof(symbol,db,mesh:{name,_ in
        if name.hasSuffix("_status") {return view(committed ? 3:published==0 ? 0:1)}
        if name.hasSuffix("_commit") {committed=true;return view(3)}
        precondition(name==symbol);published+=1
        if !committed {throw NSError(domain:"proof",code:7,userInfo:[NSLocalizedDescriptionKey:"bounty_selection_pending"])}
        return Data([42])
      },sdk:{op,_ in precondition(op==4);return raw})
      precondition(output==Data([42]) && published==2)
    }
    func movementView(_ status:UInt8)->Data {
      MeshMessengerBountyBridge.packet([Data([1,66,77,87]),Data(repeating:7,count:32),Data([status]),status>=2 ? Data(repeating:9,count:64):Data(),Data(repeating:4,count:32),Data(repeating:6,count:32),Data(repeating:5,count:32),Data(repeating:0,count:8),Data([6]),Data(repeating:0,count:8),Data(repeating:0,count:8),Data()])
    }
    func prepared(_ status:UInt8)->Data {
      var intent=Data(repeating:1,count:166);intent.replaceSubrange(0..<4,with:[1,66,87,84]);intent.replaceSubrange(44..<76,with:Data(repeating:6,count:32))
      return MeshMessengerBountyBridge.packet([Data([1,66,77,80]),Data(repeating:7,count:32),Data([status==1 ? 1:0]),intent,status>=2 ? Data(repeating:9,count:64):Data(),Data([status])])
    }
    let movementRequest=MeshMessengerBountyBridge.packet([db,Data(repeating:6,count:32)])
    var movementCalls:[String]=[]
    let moved=try MeshMessengerBountyBridge.movement(movementRequest,database:db,mesh:{name,input in
      movementCalls.append(name)
      if name.hasSuffix("_prepare") {precondition(input==MeshMessengerBountyBridge.packet([db,Data(repeating:6,count:32),Data(repeating:2,count:32)]));return prepared(1)}
      if name.hasSuffix("_commit") {precondition(input==MeshMessengerBountyBridge.packet([db,Data(repeating:7,count:32),Data(repeating:8,count:200)]));return movementView(2)}
      precondition(name.hasSuffix("_submit"));return movementView(3)
    },sdk:{op,input in movementCalls.append("sdk\(op)");if op==2 {return Data(repeating:2,count:32)};precondition(op==5 && input.count==166);return Data(repeating:8,count:200)})
    precondition(moved==movementView(3) && movementCalls==["sdk2","mesh_messenger_bounty_transfer_prepare","sdk5","mesh_messenger_bounty_transfer_commit","mesh_messenger_bounty_transfer_submit"])
    for status:UInt8 in [2,3,4,5] {
      let output=try MeshMessengerBountyBridge.movement(movementRequest,database:db,mesh:{name,_ in
        if name.hasSuffix("_prepare"){return prepared(status)}
        if name.hasSuffix("_status"){return movementView(status)}
        precondition(name.hasSuffix("_submit") && status<4);return movementView(3)
      },sdk:{op,_ in precondition(op==2);return Data(repeating:2,count:32)})
      precondition(output==movementView(status<4 ? 3:status))
    }
    do {_=try MeshMessengerBountyBridge.movement(MeshMessengerBountyBridge.packet([Data("/other".utf8),Data(repeating:6,count:32)]),database:db,mesh:{_,_ in fatalError()},sdk:{_,_ in fatalError()});fatalError("wrong database accepted")}catch{}
    try observationScopeProof(MeshMessengerBountyBridge.validateObservation)
    try mixedMovementProof()
    print("Swift bounty bridge: terminal, exact SDK commit, fallback, CAS race, disable without wallet, enable custody and malformed view passed")
  }
}


func observationScopeProof(_ validate: (String, Data, Data) throws -> Void) throws {
  let db=Data("/native/morse.db".utf8), tag=Data([2,66,77,82]), identity=Data(repeating:7,count:32)
  let pack=MeshMessengerBountyBridge.packet
  var failures:[String]=[]
  func expect(_ symbol:String,_ input:Data,_ database:Data,_ accepted:Bool,_ label:String) {
    let actual:Bool
    do {try validate(symbol,input,database);actual=true} catch {actual=false}
    if actual != accepted {failures.append("\(symbol): \(label) \(actual ? "accepted invalid" : "rejected valid")")}
  }
  for operation in ["status","recover","cancel"] {
    let symbol="mesh_messenger_bounty_transfer_\(operation)"
    let fields=operation=="status" ? [tag,db]:[tag,db,Data([1]),identity]
    let frame=pack(fields), legacy=operation=="status" ? db:pack([db,identity])
    expect(symbol,frame,db,true,"v2")
    expect(symbol,legacy,db,true,"legacy")
    if operation != "status" {for asset:UInt8 in [0,2] {expect(symbol,pack([tag,db,Data([asset]),identity]),db,true,"asset \(asset)")}}
    for valid in [frame,legacy] {
      expect(symbol,valid,Data("/other.db".utf8),false,"wrong native database")
      for end in 0..<valid.count {expect(symbol,Data(valid.prefix(end)),db,false,"truncated \(end)")}
      expect(symbol,valid+Data([0]),db,false,"trailing byte")
    }
    var malformed=[Data(repeating:0,count:8193),pack([tag]),pack([Data([3,66,77,82]),identity]),pack([db]),pack([db,identity,Data()]),pack(fields+[Data()])]
    for (index,value):(Int,Data) in [(0,Data([3,66,77,82])),(0,Data([2,66,77,87])),(0,tag+Data([0])),(0,Data()),(1,Data("/other.db".utf8)),(1,Data())] {
      var bad=fields;bad[index]=value;malformed.append(pack(bad))
    }
    for count:UInt8 in [0,1,3,5,255] {var bad=frame;bad[3]=count;malformed.append(bad)}
    var bad=frame;bad.replaceSubrange(4..<8,with:Data(repeating:255,count:4));malformed.append(bad)
    if operation != "status" {
      malformed.append(db)
      for selector in [Data(),Data([3]),Data([255]),Data([1,2])] {malformed.append(pack([tag,db,selector,identity]))}
      for identity in [Data(),Data(repeating:7,count:31),Data(repeating:7,count:33),Data(repeating:0,count:32)] {
        malformed.append(pack([tag,db,Data([1]),identity]));malformed.append(pack([db,identity]))
      }
    } else {malformed.append(pack([tag,db,Data([1]),identity]))}
    for (index,input) in malformed.enumerated() {expect(symbol,input,db,false,"malformed \(index)")}
  }
  for operation in ["prepare","commit","submit","unknown"] {
    expect("mesh_messenger_bounty_transfer_\(operation)",pack([tag,db,Data([1]),identity]),db,false,"private or unknown")
  }
  if !failures.isEmpty {
    for failure in failures {print(failure)}
    throw NSError(domain:"BountyObservationProof",code:failures.count)
  }
  print("Swift scoped bounty observation: v2 status/recover/cancel, legacy, native database and closed malformed ABI passed")
}

private func mixedMovementProof() throws {
  let pack=MeshMessengerBountyBridge.packet
  let db=Data("/db".utf8)
  func bytes(_ n:UInt8,_ count:Int)->Data {Data(repeating:n,count:count)}
  func intent(_ destination:UInt8)->Data {
    var v=Data(repeating:0,count:166)
    v.replaceSubrange(0..<4,with:[1,66,87,84]);v.replaceSubrange(12..<44,with:bytes(4,32))
    v.replaceSubrange(44..<76,with:bytes(destination,32));v.replaceSubrange(76..<108,with:bytes(5,32))
    v[115]=100;v[165]=6;return v
  }
  func row(_ status:UInt8,_ dest:UInt8)->Data {
    pack([Data([1,66,77,87]),bytes(7,32),Data([status]),status>=2 ? bytes(9,64):Data(),bytes(4,32),bytes(dest,32),bytes(5,32),Data([0,0,0,0,0,0,0,100]),Data([6]),bytes(0,8),bytes(0,8),Data()])
  }
  func aggregate(_ asset:UInt8,_ status:UInt8,_ dest:UInt8,_ availability:UInt8)->Data {
    if asset==0 {return pack([Data([2,66,77,87]),Data([1]),Data(),row(max(1,status),dest),Data(),Data()])}
    func leg(_ selector:UInt8)->Data {pack([Data([2,66,77,76]),Data([selector]),Data([selector==asset ? availability:1]),bytes(5,32),Data([0,0,0,0,0,0,0,selector==asset && availability != 1 ? 100:0]),Data([selector==asset && availability==3 ? 6:255]),selector==asset && availability==3 ? row(status,dest):Data()])}
    return pack([Data([2,66,77,87]),Data([2]),Data(),Data(),leg(1),leg(2)])
  }
  func plan(_ asset:UInt8,_ status:UInt8,_ dest:UInt8,_ availability:UInt8)->Data {
    pack([Data([2,66,77,80]),Data([asset]),status>0 ? bytes(8,32):Data(),Data([status==1 && dest==6 ? 1:0]),status>0 ? intent(dest):Data(),status>=2 ? bytes(9,64):Data(),Data([status]),aggregate(asset,status,dest,availability)])
  }
  func request(_ asset:UInt8)->Data {pack([Data([2,66,77,82]),db,Data([asset]),bytes(6,32)])}
  func split(_ input:Data)->[Data] {
    var at=4;var f:[Data]=[]
    let count=input.prefix(4).reduce(0){($0<<8)|Int($1)}
    for _ in 0..<count {let n=input[at..<at+4].reduce(0){($0<<8)|Int($1)};at+=4;f.append(input.subdata(in:at..<at+n));at+=n};return f
  }
  func replace(_ input:Data,_ index:Int,_ value:Data)->Data {var f=split(input);f[index]=value;return pack(f)}
  func withCancelledUSDC(_ value:Data)->Data {replace(value,4,split(aggregate(1,0,6,3))[4])}
  var cancelledCalls:[String]=[]
  let afterCancellation=try MeshMessengerBountyBridge.movement(request(2),database:db,mesh:{name,_ in
    cancelledCalls.append(name)
    if name.hasSuffix("_prepare") {return replace(plan(2,1,6,3),7,withCancelledUSDC(aggregate(2,1,6,3)))}
    if name.hasSuffix("_commit") {return withCancelledUSDC(aggregate(2,2,6,3))}
    precondition(name.hasSuffix("_submit"));return withCancelledUSDC(aggregate(2,3,6,3))
  },sdk:{op,input in
    cancelledCalls.append("sdk\(op)")
    if op==2 {return bytes(2,32)}
    precondition(op==5 && input==intent(6));return bytes(3,200)
  })
  precondition(afterCancellation==withCancelledUSDC(aggregate(2,3,6,3)) && cancelledCalls==["sdk2","mesh_messenger_bounty_transfer_prepare","sdk5","mesh_messenger_bounty_transfer_commit","mesh_messenger_bounty_transfer_submit"])
  for (asset,noAttempt):(UInt8,Data) in [(1,plan(1,0,6,3)),(0,replace(plan(0,0,6,3),7,pack([Data([2,66,77,87]),Data([1]),Data(),row(0,6),Data(),Data()])))] {
    do {_=try MeshMessengerBountyBridge.movement(request(asset),database:db,mesh:{name,_ in precondition(name.hasSuffix("_prepare"));return noAttempt},sdk:{op,_ in precondition(op==2);return bytes(2,32)});fatalError("cancelled attempt hidden by no-attempt plan")}catch{}
  }
  print("Swift cancelled sibling: MORSE signs once with cancelled USDC; no-attempt plans cannot hide journals")
  for asset:UInt8 in [0,1,2] {
    var calls:[String]=[]
    let output=try MeshMessengerBountyBridge.movement(request(asset),database:db,mesh:{name,input in
      calls.append(name)
      if name.hasSuffix("_prepare") {precondition(input==pack([Data([2,66,77,82]),db,Data([asset]),bytes(6,32),bytes(2,32)]));return plan(asset,1,6,3)}
      if name.hasSuffix("_commit") {precondition(input==pack([Data([2,66,77,82]),db,Data([asset]),bytes(8,32),bytes(3,200)]));return aggregate(asset,2,6,3)}
      precondition(name.hasSuffix("_submit") && input==pack([Data([2,66,77,82]),db,Data([asset]),bytes(7,32)]));return aggregate(asset,3,6,3)
    },sdk:{op,input in calls.append("sdk\(op)");if op==2 {precondition(input.isEmpty);return bytes(2,32)};precondition(op==5 && input==intent(6));return bytes(3,200)})
    precondition(output==aggregate(asset,3,6,3) && calls==["sdk2","mesh_messenger_bounty_transfer_prepare","sdk5","mesh_messenger_bounty_transfer_commit","mesh_messenger_bounty_transfer_submit"])
  }
  for asset:UInt8 in [1,2] {
    for (status,dest):(UInt8,UInt8) in [(1,10),(2,10),(3,10),(4,6),(5,6)] {
      let output=try MeshMessengerBountyBridge.movement(request(asset),database:db,mesh:{name,_ in precondition(name.hasSuffix("_prepare"));return plan(asset,status,dest,3)},sdk:{op,_ in precondition(op==2);return bytes(2,32)})
      precondition(output==aggregate(asset,status,dest,3))
    }
    for availability:UInt8 in [0,1,2] {
      let output=try MeshMessengerBountyBridge.movement(request(asset),database:db,mesh:{name,_ in precondition(name.hasSuffix("_prepare"));return plan(asset,0,6,availability)},sdk:{op,_ in precondition(op==2);return bytes(2,32)})
      precondition(output==aggregate(asset,0,6,availability))
    }
    for status:UInt8 in [2,3] {
      var calls=0
      let output=try MeshMessengerBountyBridge.movement(request(asset),database:db,mesh:{name,input in
        calls+=1;if name.hasSuffix("_prepare") {return plan(asset,status,6,3)}
        precondition(name.hasSuffix("_submit") && input==pack([Data([2,66,77,82]),db,Data([asset]),bytes(7,32)]));return aggregate(asset,3,6,3)
      },sdk:{op,_ in precondition(op==2);return bytes(2,32)})
      precondition(calls==2 && output==aggregate(asset,3,6,3))
    }
  }
  let unavailable=pack([Data([2,66,77,87]),Data([0]),Data("not configured".utf8),Data(),Data(),Data()])
  let noPlan=pack([Data([2,66,77,80]),Data([1]),Data(),Data([0]),Data(),Data(),Data([0]),unavailable])
  let noOutput=try MeshMessengerBountyBridge.movement(request(1),database:db,mesh:{_,_ in noPlan},sdk:{op,_ in precondition(op==2);return bytes(2,32)})
  precondition(noOutput==unavailable)
  let base=request(1)
  for bad in [replace(base,0,Data([3,66,77,82])),replace(base,2,Data([3])),replace(base,2,Data([1,2])),replace(base,1,Data("/other".utf8)),replace(base,3,bytes(0,32)),pack(split(base)+[Data()]),pack([Data([3,66,77,82]),bytes(6,32)]),base+Data([0]),bytes(0,8193)] {
    do {_=try MeshMessengerBountyBridge.movement(bad,database:db,mesh:{_,_ in fatalError("bad request reached Mesh")},sdk:{_,_ in fatalError("bad request reached SDK")});fatalError("bad request accepted")}catch{}
  }
  let prepared=plan(1,1,6,3),agg=aggregate(1,1,6,3),leg=split(aggregate(1,1,6,3))[4]
  let wrongIdentity=replace(row(2,6),1,bytes(11,32))
  let badAggregate=replace(agg,4,replace(leg,6,wrongIdentity))
  var badPlans=[replace(prepared,0,Data([1,66,77,80])),replace(prepared,1,Data([2])),replace(prepared,6,Data([2])),replace(prepared,7,replace(agg,4,replace(leg,1,Data([2])))),replace(prepared,7,replace(agg,4,replace(leg,5,Data([255])))),replace(prepared,7,replace(agg,2,Data([255]))),replace(prepared,7,agg+Data([0])),replace(prepared,3,Data([0])),replace(prepared,2,Data()),replace(prepared,5,bytes(9,64))]
  for offset in [0,12,44,76,108,165] {var bwt=intent(6);bwt[offset]^=1;badPlans.append(replace(prepared,4,bwt))}
  for bad in badPlans {
    do {_=try MeshMessengerBountyBridge.movement(request(1),database:db,mesh:{name,_ in precondition(name.hasSuffix("_prepare"));return bad},sdk:{op,_ in precondition(op==2);return bytes(2,32)});fatalError("bad response reached signer")}catch{}
  }
  for bad in [replace(aggregate(1,2,6,3),4,replace(leg,6,row(2,10))),badAggregate,aggregate(1,1,6,3)] {
    do {_=try MeshMessengerBountyBridge.movement(request(1),database:db,mesh:{name,_ in if name.hasSuffix("_prepare"){return prepared};precondition(name.hasSuffix("_commit"));return bad},sdk:{op,_ in op==2 ? bytes(2,32):bytes(3,200)});fatalError("bad commit reached submit")}catch{}
  }
  print("Swift mixed movement: selectors, exact signing order, pending destination, read-only states, terminal reuse and malformed ABI passed")
}
