package expo.modules.meshmessenger
private fun view(status:Int,enabled:Boolean=true)=MeshMessengerBountyBridge.packet(listOf(byteArrayOf(1,66,70,80),byteArrayOf(if(enabled)1 else 0),byteArrayOf(status.toByte()),if(status==0)byteArrayOf() else ByteArray(32){7},if(status<2)byteArrayOf() else ByteArray(32){if(status==2||status==4)0 else 8},ByteArray(8)))
fun main() {
    val db="/db".toByteArray();var calls=0;val raw=ByteArray(8)+ByteArray(32){9}
    for(status in listOf(0,2,3,4,5)) MeshMessengerBountyBridge.preflight(db,{name,input->check(name.endsWith("_status")&&input.contentEquals(db));view(status)},{_,_->error("terminal proof reached SDK")})
    MeshMessengerBountyBridge.preflight(db,{name,input->if(name.endsWith("_status"))view(1) else {check(name.endsWith("_commit")&&input.contentEquals(MeshMessengerBountyBridge.packet(listOf(db,ByteArray(32){7},raw))));view(3)}},{op,input->check(op==4&&input.isEmpty());calls++;raw})
    check(calls==1)
    MeshMessengerBountyBridge.preflight(db,{name,input->if(name.endsWith("_status"))view(1) else {check(name.endsWith("_unavailable")&&input.contentEquals(MeshMessengerBountyBridge.packet(listOf(db,ByteArray(32){7}))));view(4)}},{_,_->error("wallet locked")})
    var reads=0;calls=0
    MeshMessengerBountyBridge.preflight(db,{name,_->if(name.endsWith("_status")){reads++;view(if(reads==1)1 else 3)}else{check(name.endsWith("_commit"));error("CAS race")}},{_,_->calls++;raw})
    check(calls==1)
    check(MeshMessengerBountyBridge.setEnabled(db,0,{name,input->check(name.endsWith("_set_enabled")&&input.contentEquals(MeshMessengerBountyBridge.packet(listOf(db,byteArrayOf(0)))));view(0,false)},{_,_->error("disable needs no wallet")}).contentEquals(view(0,false)))
    check(runCatching {MeshMessengerBountyBridge.setEnabled(db,1,{_,_->error("failed SDK changed preference")},{op,_->check(op==2);error("missing wallet")})}.isFailure)
    check(runCatching {MeshMessengerBountyBridge.preflight(db,{_,_->view(1)+byteArrayOf(0)},{_,_->error("malformed view reached SDK")})}.isFailure)
    for(symbol in listOf("mesh_messenger_transparency_fork","mesh_messenger_fork_filing")) {
        var published=0;var committed=false
        val result=MeshMessengerBountyBridge.invokeProof(symbol,db,{name,_->
            if(name.endsWith("_status"))view(if(committed)3 else if(published==0)0 else 1)
            else if(name.endsWith("_commit")){committed=true;view(3)}
            else {check(name==symbol);published++;check(committed){"bounty_selection_pending"};byteArrayOf(42)}
        },{op,_->check(op==4);raw})
        check(result.contentEquals(byteArrayOf(42))&&published==2)
    }
    fun movementView(status:Int)=MeshMessengerBountyBridge.packet(listOf(byteArrayOf(1,66,77,87),ByteArray(32){7},byteArrayOf(status.toByte()),if(status>=2)ByteArray(64){9}else byteArrayOf(),ByteArray(32){4},ByteArray(32){6},ByteArray(32){5},ByteArray(8),byteArrayOf(6),ByteArray(8),ByteArray(8),byteArrayOf()))
    fun prepared(status:Int):ByteArray {
        val intent=ByteArray(166){1};byteArrayOf(1,66,87,84).copyInto(intent);ByteArray(32){6}.copyInto(intent,44)
        return MeshMessengerBountyBridge.packet(listOf(byteArrayOf(1,66,77,80),ByteArray(32){7},byteArrayOf(if(status==1)1 else 0),intent,if(status>=2)ByteArray(64){9}else byteArrayOf(),byteArrayOf(status.toByte())))
    }
    val movementRequest=MeshMessengerBountyBridge.packet(listOf(db,ByteArray(32){6}));val movementCalls=mutableListOf<String>()
    val moved=MeshMessengerBountyBridge.movement(movementRequest,db,{name,input->
        movementCalls.add(name)
        if(name.endsWith("_prepare")){check(input.contentEquals(MeshMessengerBountyBridge.packet(listOf(db,ByteArray(32){6},ByteArray(32){2}))));prepared(1)}
        else if(name.endsWith("_commit")){check(input.contentEquals(MeshMessengerBountyBridge.packet(listOf(db,ByteArray(32){7},ByteArray(200){8}))));movementView(2)}
        else {check(name.endsWith("_submit"));movementView(3)}
    },{op,input->movementCalls.add("sdk$op");if(op==2)ByteArray(32){2}else{check(op==5&&input.size==166);ByteArray(200){8}}})
    check(moved.contentEquals(movementView(3))&&movementCalls==listOf("sdk2","mesh_messenger_bounty_transfer_prepare","sdk5","mesh_messenger_bounty_transfer_commit","mesh_messenger_bounty_transfer_submit"))
    for(status in listOf(2,3,4,5)) {
        val output=MeshMessengerBountyBridge.movement(movementRequest,db,{name,_->
            if(name.endsWith("_prepare"))prepared(status)else if(name.endsWith("_status"))movementView(status)else{check(name.endsWith("_submit")&&status<4);movementView(3)}
        },{op,_->check(op==2);ByteArray(32){2}})
        check(output.contentEquals(movementView(if(status<4)3 else status)))
    }
    check(runCatching {MeshMessengerBountyBridge.movement(MeshMessengerBountyBridge.packet(listOf("/other".toByteArray(),ByteArray(32){6})),db,{_,_->error("wrong database reached Mesh")},{_,_->error("wrong database reached SDK")})}.isFailure)
    println("Kotlin bounty bridge: terminal, exact SDK commit, fallback, CAS race, disable without wallet, enable custody and malformed view passed")
}
