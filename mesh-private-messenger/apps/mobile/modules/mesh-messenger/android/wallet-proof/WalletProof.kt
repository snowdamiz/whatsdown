@file:Suppress("DEPRECATION")
package expo.modules.meshmessenger

import android.app.Activity
import android.app.Service
import android.content.Intent
import android.os.Bundle
import android.os.IBinder
import android.os.ResultReceiver
import android.test.InstrumentationTestCase
import android.view.accessibility.AccessibilityNodeInfo
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

class WalletProofActivity : Activity() {
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        System.loadLibrary("wallet_proof")
        MeshMessengerWalletStore.install(this)
        MeshMessengerWalletStore.setActivity(this)
    }
}
class WalletProofPeer : Service() {
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onStartCommand(intent: Intent?, flags: Int, id: Int): Int {
        val receiver = intent?.getParcelableExtra<ResultReceiver>("reply") ?: return START_NOT_STICKY
        thread {
            try {
                System.loadLibrary("wallet_proof")
                MeshMessengerWalletStore.install(this)
                val indices = LongArray(16) { ByteBuffer.wrap(MeshMessengerWalletStore.invoke(4, byteArrayOf())).order(ByteOrder.LITTLE_ENDIAN).long }
                receiver.send(0, Bundle().apply { putLongArray("indices", indices); putByteArray("address", MeshMessengerWalletStore.invoke(2, byteArrayOf())) })
            } catch (_: Exception) { receiver.send(1, Bundle()) }
            stopSelf(id)
        }
        return START_NOT_STICKY
    }
}

class WalletProofTest : InstrumentationTestCase() {
    private lateinit var foregroundActivity: Activity
    private fun waitForeground() {
        instrumentation.waitForIdleSync()
        repeat(100) { if (!foregroundActivity.hasWindowFocus()) Thread.sleep(20) }
        assertTrue(foregroundActivity.hasWindowFocus())
    }
    private fun invoke(operation: Int, value: ByteArray = byteArrayOf()) = MeshMessengerWalletStore.invoke(operation, value)
    private fun error(operation: Int, value: ByteArray = byteArrayOf(), status: Int) {
        try { invoke(operation, value); fail("wallet operation should reject") }
        catch (failure: IllegalStateException) { assertEquals("wallet_native_error_$status", failure.message) }
    }
    private fun button(label: String): AccessibilityNodeInfo {
        repeat(100) {
            val root = instrumentation.uiAutomation.rootInActiveWindow
            val candidates = root?.findAccessibilityNodeInfosByText(label).orEmpty()
            val found = candidates.firstOrNull { it.text?.toString()?.equals(label, ignoreCase = true) == true && it.isClickable }
            if (found != null && found.window?.isFocused == true) return found
            Thread.sleep(30)
        }
        error("confirmation button missing: $label")
    }
    private fun confirmed(operation: Int, value: ByteArray = byteArrayOf(), approve: Boolean = true): ByteArray {
        waitForeground()
        val output = AtomicReference<ByteArray>()
        val failure = AtomicReference<Throwable>()
        val worker = thread { try { output.set(invoke(operation, value)) } catch (error: Throwable) { failure.set(error) } }
        assertTrue(button(if (approve) "Create wallet" else "Cancel").performAction(AccessibilityNodeInfo.ACTION_CLICK))
        worker.join(5000)
        assertFalse("native confirmation must complete", worker.isAlive)
        failure.get()?.let { throw it }
        return output.get()
    }
    fun testNativeCustodyAndExplicitForegroundConfirmation() {
        val info = instrumentation.uiAutomation.serviceInfo
        info.flags = info.flags or android.accessibilityservice.AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
        instrumentation.uiAutomation.serviceInfo = info
        val context = instrumentation.targetContext
        val activity = instrumentation.startActivitySync(Intent(context, WalletProofActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        foregroundActivity = activity
        waitForeground()
        error(2, status = 2)
        // Cancellation creates no seed or counter record.
        val cancelled = AtomicReference<Throwable>()
        val cancelThread = thread { try { invoke(1) } catch (failure: Throwable) { cancelled.set(failure) } }
        button("Cancel").performAction(AccessibilityNodeInfo.ACTION_CLICK)
        cancelThread.join(5000)
        assertEquals("wallet_native_error_4", cancelled.get()?.message)
        error(2, status = 2)
        val address = confirmed(1)
        assertEquals(32, address.size)
        assertTrue(address.contentEquals(invoke(2)))
        val folder = File(context.noBackupFilesDir, "morse-wallet-v1-1")
        val sealed = File(folder, "wallet.sealed")
        assertEquals(80L, sealed.length())
        val initialSnapshot = sealed.readBytes()
        assertFalse(String(sealed.readBytes(), Charsets.ISO_8859_1).contains("MWL1"))
        assertFalse(File(context.filesDir, "wallet.sealed").exists())
        // Native callbacks serialize all independent application processes.
        val peerDone = CountDownLatch(1)
        var peerCode = -1
        var peer = longArrayOf()
        var peerAddress = byteArrayOf()
        val receiver = object : ResultReceiver(null) {
            override fun onReceiveResult(code: Int, result: Bundle) { peerCode = code; peer = result.getLongArray("indices") ?: longArrayOf(); peerAddress = result.getByteArray("address") ?: byteArrayOf(); peerDone.countDown() }
        }
        context.startService(Intent(context, WalletProofPeer::class.java).putExtra("reply", receiver))
        val local = Collections.synchronizedList(mutableListOf<Long>())
        val workers = List(2) { thread { repeat(8) { local.add(ByteBuffer.wrap(invoke(4)).order(ByteOrder.LITTLE_ENDIAN).long) } } }
        workers.forEach { it.join(10000); assertFalse(it.isAlive) }
        assertTrue(peerDone.await(10, TimeUnit.SECONDS))
        assertEquals(0, peerCode)
        assertTrue(address.contentEquals(peerAddress))
        assertEquals((0L..31L).toSet(), (local + peer.toList()).toSet())
        assertTrue(address.contentEquals(invoke(2)))
        // Full u64 values are displayed as exact decimal base units.
        val quote = ByteArray(256)
        byteArrayOf(1, 67, 81, 84).copyInto(quote)
        quote.fill(3, 4, 36); quote.fill(2, 36, 100)
        quote[132] = 1; quote.fill((-1).toByte(), 133, 141); quote[141] = 1
        quote[143] = 100
        val now = System.currentTimeMillis() / 1000
        ByteBuffer.wrap(quote).putLong(144, now).putLong(152, now + 900)
        quote.fill(8, 160, 192); quote.fill(9, 192, 224); quote.fill(4, 224, 256)
        val shown = MeshMessengerWalletStore.confirmation(3, quote.copyOfRange(0, 224) + address + quote.copyOfRange(224, 256), ByteArray(32) { 0x77 } + byteArrayOf(1))
        assertTrue(shown.contains("18446744073.709551615 SOL"))
        assertTrue(shown.contains("Purpose: test credits"))
        assertTrue(shown.contains("Network fees and any token-account rent are additional."))
        assertFalse(shown.contains("TEST ·"))
        val paymentIntent = quote.copyOfRange(0, 224) + address + quote.copyOfRange(224, 256)
        val nativePins = ByteArray(32) { 0x77 } + byteArrayOf(1)
        val bountyReservation = invoke(4)
        val bounty = ByteArray(166)
        byteArrayOf(1, 66, 87, 84).copyInto(bounty)
        ByteBuffer.wrap(bounty).putLong(4, ByteBuffer.wrap(bountyReservation).order(ByteOrder.LITTLE_ENDIAN).long)
        bountyReservation.copyOfRange(8, 40).copyInto(bounty, 12)
        address.copyInto(bounty, 44); bounty.fill(0x77, 76, 108)
        ByteBuffer.wrap(bounty).putLong(108, -1).putLong(148, now).putLong(156, now + 300)
        bounty.fill(4, 116, 148); bounty[164] = 1; bounty[165] = 6
        val bountyIntent = bounty + address
        val bountyText = MeshMessengerWalletStore.confirmation(5, bountyIntent, nativePins)
        assertTrue(bountyText.contains("18446744073709.551615 tokens"))
        assertTrue(bountyText.contains("links the one-time bounty address"))
        try { MeshMessengerWalletStore.confirmation(5, bountyIntent, nativePins.clone().apply { this[32] = 0 }); fail("bounty formatter must retain purpose pin") }
        catch (_: IllegalArgumentException) { }
        val cancelledBounty = AtomicReference<Throwable>()
        waitForeground()
        val cancellingBounty = thread { try { invoke(5,bounty) } catch (failure:Throwable) { cancelledBounty.set(failure) } }
        button("Cancel").performAction(AccessibilityNodeInfo.ACTION_CLICK)
        cancellingBounty.join(5000)
        assertEquals("wallet_native_error_4",cancelledBounty.get()?.message)
        val bountyWire=AtomicReference<ByteArray>();val bountyError=AtomicReference<Throwable>()
        waitForeground()
        val signingBounty=thread {try {bountyWire.set(invoke(5,bounty))}catch(failure:Throwable){bountyError.set(failure)}}
        try {button("Move bounty").performAction(AccessibilityNodeInfo.ACTION_CLICK)}
        catch(missing:Exception){bountyError.get()?.let {throw it};throw missing}
        signingBounty.join(5000);assertFalse(signingBounty.isAlive);bountyError.get()?.let {throw it}
        assertTrue(bountyWire.get().size in 130..1232)
        assertEquals(2,bountyWire.get()[0].toInt())
        val creationText = MeshMessengerWalletStore.confirmation(1, address, nativePins)
        assertTrue(creationText.contains("There is no seed export or recovery option."))
        try { MeshMessengerWalletStore.confirmation(3, paymentIntent, nativePins.clone().apply { this[32] = 0 }); fail("formatter must retain purpose pin") }
        catch (_: IllegalArgumentException) { }
        val unpinnedMintIntent = paymentIntent.clone().apply { this[132] = 0; fill(5, 100, 132) }
        try { MeshMessengerWalletStore.confirmation(3, unpinnedMintIntent, nativePins); fail("formatter must retain mint pin") }
        catch (_: IllegalArgumentException) { }
        val signed = AtomicReference<ByteArray>()
        val signError = AtomicReference<Throwable>()
        waitForeground()
        val signing = thread { try { signed.set(invoke(3, quote)) } catch (error: Throwable) { signError.set(error) } }
        try { button("Confirm payment").performAction(AccessibilityNodeInfo.ACTION_CLICK) }
        catch (missing: Exception) { signError.get()?.let { throw it }; throw missing }
        signing.join(5000)
        assertFalse(signing.isAlive)
        signError.get()?.let { throw it }
        assertTrue(signed.get().size in 66..1232)
        val wrongPurpose = quote.clone().apply { this[141] = 0 }
        error(3, wrongPurpose, 1)
        val wrongMint = quote.clone().apply { this[132] = 0; fill(5, 100, 132) }
        error(3, wrongMint, 1)
        // A real HOME transition rejects an already open prompt via native lifecycle callbacks.
        val background = AtomicReference<Throwable>()
        waitForeground()
        val pending = thread { try { invoke(5, bounty) } catch (error: Throwable) { background.set(error) } }
        button("Move bounty")
        assertTrue(instrumentation.uiAutomation.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_HOME))
        pending.join(5000)
        assertEquals("wallet_native_error_4", background.get()?.message)
        error(3, quote, 4)
        val currentSnapshot = sealed.readBytes()
        sealed.writeBytes(initialSnapshot)
        error(2, status = 3) // Valid ciphertext from before reservations is still stale.
        sealed.writeBytes(currentSnapshot)
        assertTrue(address.contentEquals(invoke(2)))
        // A malformed record, lost Keystore key, or deleted committed record
        // must never be mistaken for a new wallet or reset the bounty index.
        val corrupted = sealed.readBytes(); corrupted[30] = (corrupted[30].toInt() xor 1).toByte(); sealed.writeBytes(corrupted)
        error(2, status = 3)
        sealed.writeBytes(currentSnapshot)
        val blockedCommit = File(folder, "wallet.pending")
        assertTrue(blockedCommit.mkdir())
        error(4, status = 3) // Keystore highwater advances, but durable file replacement fails.
        assertTrue(blockedCommit.delete())
        error(2, status = 3) // Ambiguous persistence cannot expose an older counter.
        assertTrue(sealed.delete())
        error(1, status = 3)
        instrumentation.runOnMainSync { activity.finish() }
    }
}
