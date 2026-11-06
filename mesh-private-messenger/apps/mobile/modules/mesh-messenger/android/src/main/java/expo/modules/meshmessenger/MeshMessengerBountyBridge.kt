package expo.modules.meshmessenger
import java.nio.ByteBuffer

// Trusted host control only. Mesh authenticates and freezes the proof;
// the wallet SDK supplies the durable index/address reservation.
internal object MeshMessengerBountyBridge {
    private fun invalid(): Nothing = error("invalid_bounty_response")
    fun packet(fields: List<ByteArray>): ByteArray {
        val result=ByteBuffer.allocate(4+fields.sumOf {4+it.size}).putInt(fields.size)
        for(field in fields) result.putInt(field.size).put(field)
        return result.array()
    }
    private data class View(val enabled:Boolean,val status:Int,val proof:ByteArray)
    private fun view(input:ByteArray):View {
        if(input.size>160||input.size<4) invalid()
        val buffer=ByteBuffer.wrap(input)
        if(buffer.int!=6) invalid()
        val fields=ArrayList<ByteArray>()
        repeat(6) {
            if(buffer.remaining()<4) invalid()
            val size=buffer.int
            if(size<0||size>buffer.remaining()) invalid()
            val field=ByteArray(size);buffer.get(field);fields.add(field)
        }
        if(buffer.hasRemaining()||!fields[0].contentEquals(byteArrayOf(1,66,70,80))||fields[1].size!=1||fields[1][0].toInt() !in 0..1||fields[2].size!=1||fields[2][0].toInt() !in 0..5||fields[5].size!=8) invalid()
        val status=fields[2][0].toInt();val index=ByteBuffer.wrap(fields[5]).long
        if((if(status==0)fields[3].isNotEmpty() else fields[3].size!=32)||(if(status<2)fields[4].isNotEmpty() else fields[4].size!=32)||
            (if(status==3)index !in 0L until 2147483648L||fields[4].all{it.toInt()==0} else index!=0L)||
            ((status==2||status==4)&&fields[4].any{it.toInt()!=0})) invalid()
        return View(fields[1][0].toInt()==1,status,fields[3])
    }
    fun preflight(database:ByteArray,mesh:(String,ByteArray)->ByteArray,sdk:(Int,ByteArray)->ByteArray) {
        repeat(3) {
            val state=view(mesh("mesh_messenger_bounty_status",database))
            if(state.status!=1) return
            val reservation=try {Result.success(sdk(4,byteArrayOf()))} catch(error:Exception) {Result.failure(error)}
            val symbol:String;val request:ByteArray
            if(reservation.isSuccess) {
                val raw=reservation.getOrThrow()
                if(raw.size!=40) invalid()
                symbol="mesh_messenger_bounty_commit";request=packet(listOf(database,state.proof,raw))
            } else {symbol="mesh_messenger_bounty_unavailable";request=packet(listOf(database,state.proof))}
            val output=try {mesh(symbol,request)} catch(_:Exception) {return@repeat}
            if(view(output).status==1) invalid()
            return
        }
        check(view(mesh("mesh_messenger_bounty_status",database)).status!=1){"bounty_selection_pending"}
    }
    fun setEnabled(database:ByteArray,flag:Int,mesh:(String,ByteArray)->ByteArray,sdk:(Int,ByteArray)->ByteArray):ByteArray {
        require(flag in 0..1){"invalid_bounty_request"}
        if(flag==1) {val address=sdk(2,byteArrayOf());if(address.size!=32||address.all{it.toInt()==0}) invalid()}
        val result=mesh("mesh_messenger_bounty_set_enabled",packet(listOf(database,byteArrayOf(flag.toByte()))))
        if(view(result).enabled!=(flag==1)) invalid()
        return result
    }
    fun invokeProof(symbol:String,database:ByteArray,mesh:(String,ByteArray)->ByteArray,sdk:(Int,ByteArray)->ByteArray):ByteArray {
        require(symbol in listOf("mesh_messenger_transparency_fork","mesh_messenger_fork_filing")){"invalid_bounty_request"}
        repeat(3) {
            preflight(database,mesh,sdk)
            try {return mesh(symbol,database)} catch(error:Exception) {if(error.message?.contains("bounty_selection_pending")!=true) throw error}
        }
        error("bounty_selection_pending")
    }
    private fun movementFields(input:ByteArray,count:Int,maximum:Int):List<ByteArray> {
        require(input.size in 4..maximum){"invalid_bounty_transfer_response"}
        val buffer=java.nio.ByteBuffer.wrap(input)
        require(buffer.int==count){"invalid_bounty_transfer_response"}
        val fields=(0 until count).map {
            require(buffer.remaining()>=4){"invalid_bounty_transfer_response"}
            val size=buffer.int
            require(size>=0&&size<=buffer.remaining()){"invalid_bounty_transfer_response"}
            ByteArray(size).also {buffer.get(it)}
        }
        require(!buffer.hasRemaining()){"invalid_bounty_transfer_response"};return fields
    }
    private fun movementResult(input:ByteArray,identity:ByteArray,destination:ByteArray):Int {
        val f=movementFields(input,12,2048)
        require(f[0].contentEquals(byteArrayOf(1,66,77,87))&&f[1].contentEquals(identity)&&f[2].size==1&&f[2][0].toInt() in 0..5&&
            f[4].size==32&&f[5].contentEquals(destination)&&f[6].size==32&&f[7].size==8&&f[8].size==1&&f[8][0].toInt() in 0..18&&
            f[9].size==8&&f[10].size==8&&f[11].size<=256&&
            (if(f[2][0]<2)f[3].isEmpty() else f[3].size==64)){"invalid_bounty_transfer_response"}
        java.nio.charset.StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(f[11]))
        return f[2][0].toInt()
    }
    fun movement(input:ByteArray,database:ByteArray,mesh:(String,ByteArray)->ByteArray,sdk:(Int,ByteArray)->ByteArray):ByteArray {
        val request=movementFields(input,2,8192)
        require(request[0].contentEquals(database)&&request[1].size==32&&request[1].any{it.toInt()!=0}){"invalid_bounty_transfer_request"}
        val payer=sdk(2,byteArrayOf())
        require(payer.size==32&&payer.any{it.toInt()!=0}){"invalid_bounty_wallet_response"}
        val p=movementFields(mesh("mesh_messenger_bounty_transfer_prepare",packet(listOf(database,request[1],payer))),6,512)
        require(p[0].contentEquals(byteArrayOf(1,66,77,80))&&p[1].size==32&&p[1].any{it.toInt()!=0}&&p[2].size==1&&
            p[3].size==166&&p[3].copyOfRange(0,4).contentEquals(byteArrayOf(1,66,87,84))&&p[3].copyOfRange(44,76).contentEquals(request[1])&&
            p[5].size==1&&p[5][0].toInt() in 1..5&&p[2][0].toInt()==(if(p[5][0].toInt()==1)1 else 0)&&
            (if(p[5][0]<2)p[4].isEmpty() else p[4].size==64)){"invalid_bounty_transfer_response"}
        val identity=p[1]
        if(p[2][0].toInt()==1) {
            val wire=sdk(5,p[3]);require(wire.isNotEmpty()&&wire.size<=1232){"invalid_bounty_wallet_response"}
            val committed=mesh("mesh_messenger_bounty_transfer_commit",packet(listOf(database,identity,wire)))
            val status=movementResult(committed,identity,request[1]);if(status>=4)return committed
            require(status>=2){"invalid_bounty_transfer_response"}
        } else if(p[5][0]>=4) {
            val output=mesh("mesh_messenger_bounty_transfer_status",database)
            movementResult(output,identity,request[1]);return output
        }
        val output=mesh("mesh_messenger_bounty_transfer_submit",packet(listOf(database,identity)))
        require(movementResult(output,identity,request[1])>=2){"invalid_bounty_transfer_response"};return output
    }

}
