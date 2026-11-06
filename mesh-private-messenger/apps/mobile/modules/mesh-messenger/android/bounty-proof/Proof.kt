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
    observationScopeProof(MeshMessengerBountyBridge::validateObservation)
    mixedMovementProof()
    println("Kotlin bounty bridge: terminal, exact SDK commit, fallback, CAS race, disable without wallet, enable custody and malformed view passed")
}


fun observationScopeProof(validate:(String,ByteArray,ByteArray)->Unit) {
    val db="/native/morse.db".toByteArray();val tag=byteArrayOf(2,66,77,82);val identity=ByteArray(32){7}
    fun pack(vararg fields:ByteArray)=MeshMessengerBountyBridge.packet(fields.toList())
    val failures=mutableListOf<String>()
    fun expect(symbol:String,input:ByteArray,database:ByteArray,accepted:Boolean,label:String) {
        val actual=runCatching{validate(symbol,input,database)}.isSuccess
        if(actual!=accepted) failures.add("$symbol: $label ${if(actual)"accepted invalid" else "rejected valid"}")
    }
    for(operation in listOf("status","recover","cancel")) {
        val symbol="mesh_messenger_bounty_transfer_$operation"
        val fields=if(operation=="status")listOf(tag,db)else listOf(tag,db,byteArrayOf(1),identity)
        val frame=MeshMessengerBountyBridge.packet(fields);val legacy=if(operation=="status")db else pack(db,identity)
        expect(symbol,frame,db,true,"v2");expect(symbol,legacy,db,true,"legacy")
        if(operation!="status")for(asset in listOf(0,2))expect(symbol,pack(tag,db,byteArrayOf(asset.toByte()),identity),db,true,"asset $asset")
        for(valid in listOf(frame,legacy)) {
            expect(symbol,valid,"/other.db".toByteArray(),false,"wrong native database")
            for(end in 0 until valid.size)expect(symbol,valid.copyOfRange(0,end),db,false,"truncated $end")
            expect(symbol,valid+byteArrayOf(0),db,false,"trailing byte")
        }
        val malformed=mutableListOf(ByteArray(8193),pack(tag),pack(byteArrayOf(3,66,77,82),identity),pack(db),pack(db,identity,byteArrayOf()),MeshMessengerBountyBridge.packet(fields+listOf(byteArrayOf())))
        for((index,value) in listOf(0 to byteArrayOf(3,66,77,82),0 to byteArrayOf(2,66,77,87),0 to (tag+byteArrayOf(0)),0 to byteArrayOf(),1 to "/other.db".toByteArray(),1 to byteArrayOf())) {
            val bad=fields.toMutableList();bad[index]=value;malformed.add(MeshMessengerBountyBridge.packet(bad))
        }
        for(count in listOf(0,1,3,5,255)){val bad=frame.clone();bad[3]=count.toByte();malformed.add(bad)}
        val bad=frame.clone();java.nio.ByteBuffer.wrap(bad).putInt(4,-1);malformed.add(bad)
        if(operation!="status") {
            malformed.add(db)
            for(selector in listOf(byteArrayOf(),byteArrayOf(3),byteArrayOf(-1),byteArrayOf(1,2)))malformed.add(pack(tag,db,selector,identity))
            for(identity in listOf(byteArrayOf(),ByteArray(31){7},ByteArray(33){7},ByteArray(32))) {
                malformed.add(pack(tag,db,byteArrayOf(1),identity));malformed.add(pack(db,identity))
            }
        } else malformed.add(pack(tag,db,byteArrayOf(1),identity))
        for((index,input) in malformed.withIndex())expect(symbol,input,db,false,"malformed $index")
    }
    for(operation in listOf("prepare","commit","submit","unknown"))expect("mesh_messenger_bounty_transfer_$operation",pack(tag,db,byteArrayOf(1),identity),db,false,"private or unknown")
    failures.forEach(::println);check(failures.isEmpty()){"${failures.size} scoped bounty observation failures"}
    println("Kotlin scoped bounty observation: v2 status/recover/cancel, legacy, native database and closed malformed ABI passed")
}

private fun mixedMovementProof() {
    val db="/db".toByteArray()
    fun pack(vararg f:ByteArray)=MeshMessengerBountyBridge.packet(f.toList())
    fun bytes(n:Int,count:Int)=ByteArray(count){n.toByte()}
    fun intent(dest:Int):ByteArray {
        val v=bytes(0,166);byteArrayOf(1,66,87,84).copyInto(v);bytes(4,32).copyInto(v,12)
        bytes(dest,32).copyInto(v,44);bytes(5,32).copyInto(v,76);v[115]=100;v[165]=6;return v
    }
    fun row(status:Int,dest:Int)=pack(byteArrayOf(1,66,77,87),bytes(7,32),byteArrayOf(status.toByte()),if(status>=2)bytes(9,64)else byteArrayOf(),bytes(4,32),bytes(dest,32),bytes(5,32),byteArrayOf(0,0,0,0,0,0,0,100),byteArrayOf(6),bytes(0,8),bytes(0,8),byteArrayOf())
    fun aggregate(asset:Int,status:Int,dest:Int,availability:Int):ByteArray {
        if(asset==0)return pack(byteArrayOf(2,66,77,87),byteArrayOf(1),byteArrayOf(),row(maxOf(1,status),dest),byteArrayOf(),byteArrayOf())
        fun leg(selector:Int)=pack(byteArrayOf(2,66,77,76),byteArrayOf(selector.toByte()),byteArrayOf((if(selector==asset)availability else 1).toByte()),bytes(5,32),byteArrayOf(0,0,0,0,0,0,0,if(selector==asset&&availability!=1)100 else 0),byteArrayOf((if(selector==asset&&availability==3)6 else 255).toByte()),if(selector==asset&&availability==3)row(status,dest)else byteArrayOf())
        return pack(byteArrayOf(2,66,77,87),byteArrayOf(2),byteArrayOf(),byteArrayOf(),leg(1),leg(2))
    }
    fun plan(asset:Int,status:Int,dest:Int,availability:Int)=pack(byteArrayOf(2,66,77,80),byteArrayOf(asset.toByte()),if(status>0)bytes(8,32)else byteArrayOf(),byteArrayOf(if(status==1&&dest==6)1 else 0),if(status>0)intent(dest)else byteArrayOf(),if(status>=2)bytes(9,64)else byteArrayOf(),byteArrayOf(status.toByte()),aggregate(asset,status,dest,availability))
    fun request(asset:Int)=pack(byteArrayOf(2,66,77,82),db,byteArrayOf(asset.toByte()),bytes(6,32))
    fun split(input:ByteArray):List<ByteArray> {val b=java.nio.ByteBuffer.wrap(input);return (0 until b.int).map{ByteArray(b.int).also{b.get(it)}}}
    fun replace(input:ByteArray,index:Int,value:ByteArray):ByteArray {val f=split(input).toMutableList();f[index]=value;return MeshMessengerBountyBridge.packet(f)}
    fun withCancelledUSDC(value:ByteArray)=replace(value,4,split(aggregate(1,0,6,3))[4])
    val cancelledCalls=mutableListOf<String>()
    val afterCancellation=MeshMessengerBountyBridge.movement(request(2),db,{name,_->
        cancelledCalls.add(name)
        if(name.endsWith("_prepare"))replace(plan(2,1,6,3),7,withCancelledUSDC(aggregate(2,1,6,3)))
        else if(name.endsWith("_commit"))withCancelledUSDC(aggregate(2,2,6,3))
        else {check(name.endsWith("_submit"));withCancelledUSDC(aggregate(2,3,6,3))}
    },{op,input->cancelledCalls.add("sdk$op");if(op==2)bytes(2,32)else{check(op==5&&input.contentEquals(intent(6)));bytes(3,200)}})
    check(afterCancellation.contentEquals(withCancelledUSDC(aggregate(2,3,6,3)))&&cancelledCalls==listOf("sdk2","mesh_messenger_bounty_transfer_prepare","sdk5","mesh_messenger_bounty_transfer_commit","mesh_messenger_bounty_transfer_submit"))
    for((asset,noAttempt) in listOf(1 to plan(1,0,6,3),0 to replace(plan(0,0,6,3),7,pack(byteArrayOf(2,66,77,87),byteArrayOf(1),byteArrayOf(),row(0,6),byteArrayOf(),byteArrayOf())))) {
        check(runCatching{MeshMessengerBountyBridge.movement(request(asset),db,{name,_->check(name.endsWith("_prepare"));noAttempt},{op,_->check(op==2);bytes(2,32)})}.isFailure)
    }
    println("Kotlin cancelled sibling: MORSE signs once with cancelled USDC; no-attempt plans cannot hide journals")
    for(asset in listOf(0,1,2)) {
        val calls=mutableListOf<String>()
        val output=MeshMessengerBountyBridge.movement(request(asset),db,{name,input->
            calls.add(name)
            if(name.endsWith("_prepare")){check(input.contentEquals(pack(byteArrayOf(2,66,77,82),db,byteArrayOf(asset.toByte()),bytes(6,32),bytes(2,32))));plan(asset,1,6,3)}
            else if(name.endsWith("_commit")){check(input.contentEquals(pack(byteArrayOf(2,66,77,82),db,byteArrayOf(asset.toByte()),bytes(8,32),bytes(3,200))));aggregate(asset,2,6,3)}
            else {check(name.endsWith("_submit")&&input.contentEquals(pack(byteArrayOf(2,66,77,82),db,byteArrayOf(asset.toByte()),bytes(7,32))));aggregate(asset,3,6,3)}
        },{op,input->calls.add("sdk$op");if(op==2){check(input.isEmpty());bytes(2,32)}else{check(op==5&&input.contentEquals(intent(6)));bytes(3,200)}})
        check(output.contentEquals(aggregate(asset,3,6,3))&&calls==listOf("sdk2","mesh_messenger_bounty_transfer_prepare","sdk5","mesh_messenger_bounty_transfer_commit","mesh_messenger_bounty_transfer_submit"))
    }
    for(asset in listOf(1,2)) {
        for((status,dest) in listOf(1 to 10,2 to 10,3 to 10,4 to 6,5 to 6)) {
            val output=MeshMessengerBountyBridge.movement(request(asset),db,{name,_->check(name.endsWith("_prepare"));plan(asset,status,dest,3)},{op,_->check(op==2);bytes(2,32)})
            check(output.contentEquals(aggregate(asset,status,dest,3)))
        }
        for(availability in listOf(0,1,2)) {
            val output=MeshMessengerBountyBridge.movement(request(asset),db,{name,_->check(name.endsWith("_prepare"));plan(asset,0,6,availability)},{op,_->check(op==2);bytes(2,32)})
            check(output.contentEquals(aggregate(asset,0,6,availability)))
        }
        for(status in listOf(2,3)) {
            var calls=0
            val output=MeshMessengerBountyBridge.movement(request(asset),db,{name,input->calls++
                if(name.endsWith("_prepare"))plan(asset,status,6,3)else{check(name.endsWith("_submit")&&input.contentEquals(pack(byteArrayOf(2,66,77,82),db,byteArrayOf(asset.toByte()),bytes(7,32))));aggregate(asset,3,6,3)}
            },{op,_->check(op==2);bytes(2,32)})
            check(calls==2&&output.contentEquals(aggregate(asset,3,6,3)))
        }
    }
    val unavailable=pack(byteArrayOf(2,66,77,87),byteArrayOf(0),"not configured".toByteArray(),byteArrayOf(),byteArrayOf(),byteArrayOf())
    val noPlan=pack(byteArrayOf(2,66,77,80),byteArrayOf(1),byteArrayOf(),byteArrayOf(0),byteArrayOf(),byteArrayOf(),byteArrayOf(0),unavailable)
    check(MeshMessengerBountyBridge.movement(request(1),db,{_,_->noPlan},{op,_->check(op==2);bytes(2,32)}).contentEquals(unavailable))
    val base=request(1)
    for(bad in listOf(replace(base,0,byteArrayOf(3,66,77,82)),replace(base,2,byteArrayOf(3)),replace(base,2,byteArrayOf(1,2)),replace(base,1,"/other".toByteArray()),replace(base,3,bytes(0,32)),MeshMessengerBountyBridge.packet(split(base)+listOf(byteArrayOf())),pack(byteArrayOf(3,66,77,82),bytes(6,32)),base+byteArrayOf(0),bytes(0,8193))) {
        var calls=0
        check(runCatching{MeshMessengerBountyBridge.movement(bad,db,{_,_->calls++;error("bad request reached Mesh")},{_,_->calls++;error("bad request reached SDK")})}.isFailure)
        check(calls==0)
    }
    val prepared=plan(1,1,6,3);val agg=aggregate(1,1,6,3);val leg=split(agg)[4]
    val badAggregate=replace(agg,4,replace(leg,6,replace(row(2,6),1,bytes(11,32))))
    val badPlans=mutableListOf(replace(prepared,0,byteArrayOf(1,66,77,80)),replace(prepared,1,byteArrayOf(2)),replace(prepared,6,byteArrayOf(2)),replace(prepared,7,replace(agg,4,replace(leg,1,byteArrayOf(2)))),replace(prepared,7,replace(agg,4,replace(leg,5,byteArrayOf(-1)))),replace(prepared,7,replace(agg,2,byteArrayOf(-1))),replace(prepared,7,agg+byteArrayOf(0)),replace(prepared,3,byteArrayOf(0)),replace(prepared,2,byteArrayOf()),replace(prepared,5,bytes(9,64)))
    for(offset in listOf(0,12,44,76,108,165)){val bwt=intent(6);bwt[offset]=(bwt[offset].toInt() xor 1).toByte();badPlans.add(replace(prepared,4,bwt))}
    for(bad in badPlans) {
        var extraCalls=0
        check(runCatching{MeshMessengerBountyBridge.movement(request(1),db,{name,_->if(!name.endsWith("_prepare"))extraCalls++;bad},{op,_->if(op!=2)extraCalls++;bytes(2,32)})}.isFailure)
        check(extraCalls==0)
    }
    for(bad in listOf(replace(aggregate(1,2,6,3),4,replace(leg,6,row(2,10))),badAggregate,aggregate(1,1,6,3))) {
        var submitted=false
        check(runCatching{MeshMessengerBountyBridge.movement(request(1),db,{name,_->if(name.endsWith("_prepare"))prepared else{if(!name.endsWith("_commit"))submitted=true;bad}},{op,_->if(op==2)bytes(2,32)else bytes(3,200)})}.isFailure)
        check(!submitted)
    }
    println("Kotlin mixed movement: selectors, exact signing order, pending destination, read-only states, terminal reuse and malformed ABI passed")
}
