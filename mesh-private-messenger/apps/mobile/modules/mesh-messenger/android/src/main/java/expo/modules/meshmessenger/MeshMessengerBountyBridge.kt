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
    fun validateObservation(symbol:String,input:ByteArray,database:ByteArray) {
        require(symbol in listOf("mesh_messenger_bounty_transfer_status","mesh_messenger_bounty_transfer_recover","mesh_messenger_bounty_transfer_cancel")&&database.size in 1..4096&&input.size<=8192){"invalid_bounty_transfer_request"}
        val status=symbol.endsWith("_status")
        if(status&&input.contentEquals(database))return
        require(input.size>=4){"invalid_bounty_transfer_request"}
        val count=ByteBuffer.wrap(input).int
        require(count==2||(!status&&count==4)){"invalid_bounty_transfer_request"}
        val f=movementFields(input,count,8192)
        val path=if(f[0].contentEquals(byteArrayOf(2,66,77,82))) {
            require(count==(if(status)2 else 4)){"invalid_bounty_transfer_request"}
            if(!status)require(f[2].size==1&&f[2][0].toInt() in 0..2&&f[3].size==32&&f[3].any{it.toInt()!=0}){"invalid_bounty_transfer_request"}
            f[1]
        } else {
            require(!status&&count==2&&!(f[0].size==4&&f[0].copyOfRange(1,4).contentEquals(byteArrayOf(66,77,82)))&&f[1].size==32&&f[1].any{it.toInt()!=0}){"invalid_bounty_transfer_request"}
            f[0]
        }
        require(path.contentEquals(database)){"invalid_database_path"}
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
    private fun movementRow(input:ByteArray):List<ByteArray> {
        val f=movementFields(input,12,2048)
        require(f[0].contentEquals(byteArrayOf(1,66,77,87))&&f[2].size==1&&f[2][0].toInt() in 0..5&&
            f[7].size==8&&f[8].size==1&&f[8][0].toInt() in 0..18&&f[9].size==8&&f[10].size==8&&f[11].size<=256){"invalid_bounty_transfer_response"}
        java.nio.charset.StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(f[11]))
        if(f[1].isEmpty()) {
            require(f[2][0].toInt()==0&&listOf(3,4,5,6).all{f[it].isEmpty()}){"invalid_bounty_transfer_response"}
        } else {
            require(f[1].size==32&&f[1].any{it.toInt()!=0}&&listOf(4,5,6).all{f[it].size==32}&&
                (if(f[2][0]<2)f[3].isEmpty() else f[3].size==64)){"invalid_bounty_transfer_response"}
        }
        return f
    }
    private fun movementAggregate(input:ByteArray,asset:Int):List<ByteArray>? {
        val f=movementFields(input,6,8192)
        require(f[0].contentEquals(byteArrayOf(2,66,77,87))&&f[1].size==1&&f[1][0].toInt() in 0..2&&f[2].size<=256){"invalid_bounty_transfer_response"}
        java.nio.charset.StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(f[2]))
        return when(f[1][0].toInt()) {
            0->{require(f.drop(3).all{it.isEmpty()}){"invalid_bounty_transfer_response"};null}
            1->{
                require(f[3].isNotEmpty()&&f[4].isEmpty()&&f[5].isEmpty()){"invalid_bounty_transfer_response"}
                val row=movementRow(f[3]);if(asset==0&&row[1].isNotEmpty())row else null
            }
            else->{
                require(f[3].isEmpty()){"invalid_bounty_transfer_response"}
                var selected:List<ByteArray>?=null
                for(selector in listOf(1,2)) {
                    val leg=movementFields(f[selector+3],7,4096)
                    require(leg[0].contentEquals(byteArrayOf(2,66,77,76))&&leg[1].contentEquals(byteArrayOf(selector.toByte()))&&
                        leg[2].size==1&&leg[2][0].toInt() in 0..3&&leg[3].size==32&&leg[4].size==8&&leg[5].size==1&&
                        ((leg[5][0].toInt() and 255)<=18||((leg[5][0].toInt() and 255)==255&&leg[2][0].toInt()!=3))){"invalid_bounty_transfer_response"}
                    if(leg[2][0].toInt()==3) {
                        val row=movementRow(leg[6])
                        require(row[1].isNotEmpty()&&row[6].contentEquals(leg[3])&&row[7].contentEquals(leg[4])&&row[8].contentEquals(leg[5])){"invalid_bounty_transfer_response"}
                        if(selector==asset)selected=row
                    } else require(leg[6].isEmpty()){"invalid_bounty_transfer_response"}
                }
                selected
            }
        }
    }
    private fun movementMatches(row:List<ByteArray>,identity:ByteArray,intent:ByteArray):Boolean =
        row[1].contentEquals(identity)&&row[4].contentEquals(intent.copyOfRange(12,44))&&row[5].contentEquals(intent.copyOfRange(44,76))&&
            row[6].contentEquals(intent.copyOfRange(76,108))&&row[7].contentEquals(intent.copyOfRange(108,116))&&row[8].contentEquals(intent.copyOfRange(165,166))
    private fun movementV2(request:List<ByteArray>,database:ByteArray,mesh:(String,ByteArray)->ByteArray,sdk:(Int,ByteArray)->ByteArray):ByteArray {
        require(request.size==4&&request[1].contentEquals(database)&&request[2].size==1&&request[2][0].toInt() in 0..2&&
            request[3].size==32&&request[3].any{it.toInt()!=0}){"invalid_bounty_transfer_request"}
        val asset=request[2][0].toInt();val tag=byteArrayOf(2,66,77,82)
        val payer=sdk(2,byteArrayOf())
        require(payer.size==32&&payer.any{it.toInt()!=0}){"invalid_bounty_wallet_response"}
        val raw=mesh("mesh_messenger_bounty_transfer_prepare",packet(listOf(tag,database,request[2],request[3],payer)))
        val p=movementFields(raw,8,8192)
        require(p[0].contentEquals(byteArrayOf(2,66,77,80))&&p[1].contentEquals(request[2])&&p[3].size==1&&p[3][0].toInt() in 0..1&&
            p[6].size==1&&p[6][0].toInt() in 0..5){"invalid_bounty_transfer_response"}
        val selected=movementAggregate(p[7],asset);val status=p[6][0].toInt()
        if(status==0) {
            require(p[2].isEmpty()&&p[3][0].toInt()==0&&p[4].isEmpty()&&p[5].isEmpty()&&selected==null){"invalid_bounty_transfer_response"}
            return p[7]
        }
        require(p[2].size==32&&p[2].any{it.toInt()!=0}&&p[4].size==166&&p[4].copyOfRange(0,4).contentEquals(byteArrayOf(1,66,87,84))&&
            (if(status<2)p[5].isEmpty()else p[5].size==64)){"invalid_bounty_transfer_response"}
        val row=requireNotNull(selected){"invalid_bounty_transfer_response"};val identity=row[1]
        require(row[2].contentEquals(p[6])&&row[3].contentEquals(p[5])&&movementMatches(row,identity,p[4])){"invalid_bounty_transfer_response"}
        val sameDestination=p[4].copyOfRange(44,76).contentEquals(request[3])
        require(p[3][0].toInt()==(if(status==1&&sameDestination)1 else 0)){"invalid_bounty_transfer_response"}
        if(!sameDestination||status>=4)return p[7]
        if(p[3][0].toInt()==1) {
            val wire=sdk(5,p[4]);require(wire.isNotEmpty()&&wire.size<=1232){"invalid_bounty_wallet_response"}
            val committed=mesh("mesh_messenger_bounty_transfer_commit",packet(listOf(tag,database,request[2],p[2],wire)))
            val committedRow=requireNotNull(movementAggregate(committed,asset)){"invalid_bounty_transfer_response"}
            require(committedRow[2][0]>=2&&movementMatches(committedRow,identity,p[4])){"invalid_bounty_transfer_response"}
            if(committedRow[2][0]>=4)return committed
        }
        val output=mesh("mesh_messenger_bounty_transfer_submit",packet(listOf(tag,database,request[2],identity)))
        val submittedRow=requireNotNull(movementAggregate(output,asset)){"invalid_bounty_transfer_response"}
        require(submittedRow[2][0]>=2&&movementMatches(submittedRow,identity,p[4])){"invalid_bounty_transfer_response"}
        return output
    }
    fun movement(input:ByteArray,database:ByteArray,mesh:(String,ByteArray)->ByteArray,sdk:(Int,ByteArray)->ByteArray):ByteArray {
        require(input.size>=4){"invalid_bounty_transfer_request"}
        val count=ByteBuffer.wrap(input).int
        require(count==2||count==4){"invalid_bounty_transfer_request"}
        val request=movementFields(input,count,8192)
        if(request[0].contentEquals(byteArrayOf(2,66,77,82)))return movementV2(request,database,mesh,sdk)
        require(count==2&&!(request[0].size==4&&request[0].copyOfRange(1,4).contentEquals(byteArrayOf(66,77,82)))){"invalid_bounty_transfer_request"}
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
