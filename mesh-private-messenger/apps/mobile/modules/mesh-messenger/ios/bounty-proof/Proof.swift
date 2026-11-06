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
    print("Swift bounty bridge: terminal, exact SDK commit, fallback, CAS race, disable without wallet, enable custody and malformed view passed")
  }
}
