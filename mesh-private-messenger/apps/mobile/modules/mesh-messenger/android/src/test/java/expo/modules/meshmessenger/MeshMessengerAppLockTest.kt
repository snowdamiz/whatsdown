package expo.modules.meshmessenger

import android.app.Activity
import android.app.Application
import android.app.Dialog
import android.app.KeyguardManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.os.Bundle
import android.os.Looper
import android.view.WindowManager
import android.widget.TextView
import com.facebook.react.ReactActivity
import com.facebook.react.ReactActivityDelegate
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.android.controller.ActivityController
import org.robolectric.shadows.ShadowKeyguardManager
import org.robolectric.shadows.ShadowClipboardManager
import org.robolectric.shadows.ShadowLooper
import java.lang.ref.WeakReference
import java.io.File
import java.util.UUID
import java.util.concurrent.ExecutionException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** Actual controller with fake native OS/persistence boundaries. No real OS auth claim. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk=[28], application=MeshMessengerAppLockTest.NativeRuntimeApplication::class, manifest=Config.NONE, shadows=[MeshMessengerAppLockTest.CredentialOS::class,MeshMessengerAppLockTest.ClipboardOS::class])
class MeshMessengerAppLockTest {
    @Implements(value=KeyguardManager::class)
    class CredentialOS : ShadowKeyguardManager() {
        @Implementation protected fun createConfirmDeviceCredentialIntent(title: CharSequence?, description: CharSequence?): Intent = Intent("test.owned.OS_CREDENTIAL")
    }
    @Implements(value=ClipboardManager::class)
    class ClipboardOS : ShadowClipboardManager() {
        companion object { var beforeSet: (() -> Unit)? = null }
        @Implementation protected override fun setPrimaryClip(clip: ClipData) {
            beforeSet?.invoke()
            super.setPrimaryClip(clip)
        }
    }
    class Owner : ReactActivity() {
        override fun onCreate(state: Bundle?) { setTheme(androidx.appcompat.R.style.Theme_AppCompat); super.onCreate(state) }
        override fun createReactActivityDelegate() = object : ReactActivityDelegate(this,null) {
            override fun onCreate(state: Bundle?) = Unit
            override fun onResume() = Unit
            override fun onPause() = Unit
            override fun onDestroy() = Unit
            override fun onWindowFocusChanged(focused: Boolean) = Unit
            override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) = Unit
        }
    }
    private class Policy(var value: MeshMessengerAppLockPolicy.Record) : MeshMessengerAppLockPolicyPort {
        val writes=mutableListOf<String>()
        var afterWrite: ((String) -> Unit)? = null
        var beforeLoad: (() -> Unit)? = null
        override fun load(): MeshMessengerAppLockPolicy.Record { beforeLoad?.invoke();return value }
        override fun transition(previous: MeshMessengerAppLockPolicy.Record, desired: String): MeshMessengerAppLockPolicy.Record {
            check(value==previous);value=value.copy(sequence=value.sequence+1,policy=desired);writes.add(desired);afterWrite?.invoke(desired);return value
        }
    }
    private lateinit var activity: ActivityController<Owner>
    private lateinit var executor: ExecutorService
    private lateinit var policy: Policy
    private fun field(name: String)=MeshMessengerAppLock::class.java.getDeclaredField(name).apply { isAccessible=true }
    @Suppress("UNCHECKED_CAST") private fun epoch()=field("epoch").get(MeshMessengerAppLock) as AtomicReference<String>
    @Suppress("UNCHECKED_CAST") private fun pending()=(field("challenge").get(MeshMessengerAppLock) as AtomicReference<Any?>).get()
    private fun property(value: Any,name: String)=value.javaClass.getDeclaredField(name).apply { isAccessible=true }.get(value)
    private fun settle() { shadowOf(Looper.getMainLooper()).idle() }
    private fun waitFor(body: () -> Boolean) {
        val end=System.nanoTime()+TimeUnit.SECONDS.toNanos(5)
        while(!body()) { settle();check(System.nanoTime()<end) { "test_native_boundary_timeout" };Thread.sleep(2) }
        settle()
    }
    private fun configure(mode: String) {
        val record=MeshMessengerAppLockPolicy.Record(UUID.randomUUID().toString(),0,mode)
        policy=Policy(record);field("store").set(MeshMessengerAppLock,policy);field("record").set(MeshMessengerAppLock,record)
        field("phase").set(MeshMessengerAppLock,if(mode=="disabled")"disabled" else "locked")
        field("fault").set(MeshMessengerAppLock,null);field("restricted").setBoolean(MeshMessengerAppLock,mode!="disabled")
        field("owner").set(MeshMessengerAppLock,WeakReference(activity.get()));field("resumed").setBoolean(MeshMessengerAppLock,true)
        // This is a test-only native-window observation, never a production API.
        field("ownedForeground").setBoolean(MeshMessengerAppLock,true);epoch().set(UUID.randomUUID().toString())
    }
    @Before fun before() {
        executor=Executors.newSingleThreadExecutor()
        field("application").set(MeshMessengerAppLock,null)
        MeshMessengerAppLock.install(RuntimeEnvironment.getApplication())
        // Wait for the real boot worker before injecting fake durable storage.
        (field("worker").get(MeshMessengerAppLock) as ExecutorService).submit {}.get(5,TimeUnit.SECONDS)
        activity=Robolectric.buildActivity(Owner::class.java).create().start().resume().visible()
        settle();configure("enabled")
        shadowOf(RuntimeEnvironment.getApplication().getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).setIsDeviceSecure(true)
    }
    @After fun after() {
        ClipboardOS.beforeSet=null
        pending()?.let { MeshMessengerAppLock.cancel(property(it,"id") as String) }
        settle();activity.pause().stop().destroy();settle();executor.shutdownNow();assertTrue(executor.awaitTermination(5,TimeUnit.SECONDS))
    }
    private fun start(desired: Boolean?=null): Pair<Future<Map<String,Any>>,Any> {
        val expected=MeshMessengerAppLock.currentEpoch()
        val result=executor.submit<Map<String,Any>> { MeshMessengerAppLock.authenticate(expected,desired) }
        waitFor { pending()!=null };val request=pending()!!
        field("ownedForeground").setBoolean(MeshMessengerAppLock,true)
        return result to request
    }
    private fun approve(request: Any) {
        field("ownedForeground").setBoolean(MeshMessengerAppLock,true)
        assertTrue(MeshMessengerAppLock.activityResult(activity.get(),property(request,"code") as Int,Activity.RESULT_OK,null));settle()
    }
    @Test fun staleQueuedAuthenticationDoesNotRevokeNewUnlock() {
        val old=MeshMessengerAppLock.currentEpoch();val (future,request)=start();approve(request)
        val current=future.get(5,TimeUnit.SECONDS);settle();val currentEpoch=current["epoch"]
        val failed=executor.submit { MeshMessengerAppLock.authenticate(old) }
        assertThrows(ExecutionException::class.java) { failed.get(5,TimeUnit.SECONDS) }
        assertEquals(currentEpoch,MeshMessengerAppLock.state()["epoch"]);assertEquals("unlocked",MeshMessengerAppLock.state()["phase"])
    }
    @Test fun firstOptInCancellationRestoresOnlyFreshDisabledScope() {
        configure("disabled");val old=MeshMessengerAppLock.currentEpoch();val (future,request)=start(true)
        MeshMessengerAppLock.cancel(property(request,"id") as String)
        assertThrows(ExecutionException::class.java) { future.get(5,TimeUnit.SECONDS) }
        assertEquals("disabled",MeshMessengerAppLock.state()["phase"]);assertNotEquals(old,MeshMessengerAppLock.state()["epoch"]);assertTrue(policy.writes.isEmpty())
    }
    @Test fun credentialResultRequiresExactOwnerAndRequestThenEnablesThroughPending() {
        configure("disabled");val (future,request)=start(true);val code=property(request,"code") as Int
        assertFalse(MeshMessengerAppLock.activityResult(Activity(),code,Activity.RESULT_OK,null))
        assertFalse(MeshMessengerAppLock.activityResult(activity.get(),code+1,Activity.RESULT_OK,null));assertFalse(future.isDone)
        approve(request);assertEquals("enabled",future.get(5,TimeUnit.SECONDS)["policy"])
        assertEquals(listOf("enable_pending","enabled"),policy.writes)
    }
    @Test fun committedDisableLosingForegroundRequiresFreshOSRecovery() {
        policy.afterWrite={ mode -> if(mode=="disabled")MeshMessengerAppLock.invalidate("test_background",false) }
        val (future,request)=start(false);approve(request)
        assertThrows(ExecutionException::class.java) { future.get(5,TimeUnit.SECONDS) }
        assertEquals("disabled",policy.value.policy);assertEquals("locked",MeshMessengerAppLock.state()["phase"])
        val (recovery,owned)=start();assertFalse(recovery.isDone);approve(owned)
        assertEquals("disabled",recovery.get(5,TimeUnit.SECONDS)["phase"])
    }
    @Test fun repeatedResumeRetainsOneListenerAndDestroyRemovesIt() {
        repeat(3) { activity.pause().resume();settle() }
        // Inspect the actual Android observer registrations, not merely the
        // controller's map (overwriting that map could hide duplicate callbacks).
        val observer=activity.get().window.decorView.viewTreeObserver
        val copy=observer.javaClass.getDeclaredField("mOnWindowFocusListeners").apply { isAccessible=true }.get(observer)
        // SDK28 declares this field as the public JDK collection type; it has no
        // Android CopyOnWriteArray.mData field. Inspect actual registrations.
        val registered=copy as java.util.concurrent.CopyOnWriteArrayList<*>
        assertEquals(1,registered.count { it!!.javaClass.name.startsWith("expo.modules.meshmessenger.MeshMessengerAppLock") })
        val listeners=field("focusListeners").get(MeshMessengerAppLock) as Map<*,*>
        assertEquals(1,listeners.size)
        activity.pause().stop().destroy();settle();assertEquals(0,listeners.size)
        assertEquals(0,registered.count { it!!.javaClass.name.startsWith("expo.modules.meshmessenger.MeshMessengerAppLock") })
        // Recreate for deterministic after() cleanup.
        activity=Robolectric.buildActivity(Owner::class.java).create().start().resume().visible();settle()
    }
    @Test fun nativeCoverUsesSecureDialogAboveExistingAppDialogAndStaleReadinessCannotHideIt() {
        val modal=Dialog(activity.get()).apply { setContentView(TextView(context).apply { text="private test content" });show() }
        try {
            val old=MeshMessengerAppLock.currentEpoch();MeshMessengerAppLock.lock();settle()
            val covers=field("covers").get(MeshMessengerAppLock) as Map<*,*>
            val cover=covers[activity.get()] as Dialog
            assertNotSame(modal,cover);assertTrue(cover.isShowing)
            assertTrue(cover.window!!.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0)
            assertThrows(IllegalStateException::class.java) { MeshMessengerAppLock.activate(old) };assertTrue(cover.isShowing)
        } finally { modal.dismiss() }
    }
    @Test fun observedCredentialSuccessThenCancelCannotRestoreDisabled() {
        configure("disabled");val (future,request)=start(true)
        field("ownedForeground").setBoolean(MeshMessengerAppLock,false)
        assertTrue(MeshMessengerAppLock.activityResult(activity.get(),property(request,"code") as Int,Activity.RESULT_OK,null))
        assertTrue(property(request,"approved") as Boolean);assertFalse(future.isDone)
        MeshMessengerAppLock.cancel(property(request,"id") as String)
        assertThrows(ExecutionException::class.java) { future.get(5,TimeUnit.SECONDS) }
        assertEquals("locked",MeshMessengerAppLock.state()["phase"]);assertTrue(policy.writes.isEmpty())
    }
    @Test fun manualLockCannotBeOverwrittenByFirstOptInCancellation() {
        configure("disabled");val (future,_)=start(true);MeshMessengerAppLock.lock()
        assertThrows(ExecutionException::class.java) { future.get(5,TimeUnit.SECONDS) }
        assertEquals("locked",MeshMessengerAppLock.state()["phase"])
    }
    @Test fun accountChangeCannotBeOverwrittenByFirstOptInCancellation() {
        configure("disabled");val (future,_)=start(true);MeshMessengerAppLock.accountChanging()
        assertThrows(ExecutionException::class.java) { future.get(5,TimeUnit.SECONDS) }
        assertEquals("locked",MeshMessengerAppLock.state()["phase"])
    }
    @Test fun plainUnlockRefusesChangedDurablePolicy() {
        val (future,request)=start();policy.value=policy.value.copy(sequence=policy.value.sequence+1,policy="disable_pending")
        approve(request)
        assertThrows(ExecutionException::class.java) { future.get(5,TimeUnit.SECONDS) }
        assertNotEquals("unlocked",MeshMessengerAppLock.state()["phase"])
    }
    @Test fun noopEnableRefusesUnreadableDurablePolicy() {
        val (future,request)=start(true);policy.beforeLoad={ error("test_native_policy_unreadable") };approve(request)
        assertThrows(ExecutionException::class.java) { future.get(5,TimeUnit.SECONDS) }
        assertEquals("error",MeshMessengerAppLock.state()["phase"])
    }
    private fun beginReboot(): Future<*> {
        val worker=field("worker").get(MeshMessengerAppLock) as ExecutorService
        val entered=CountDownLatch(1);val release=CountDownLatch(1)
        worker.submit { entered.countDown();check(release.await(5,TimeUnit.SECONDS)) }
        check(entered.await(5,TimeUnit.SECONDS))
        try {
            field("application").set(MeshMessengerAppLock,null);field("record").set(MeshMessengerAppLock,null)
            field("phase").set(MeshMessengerAppLock,"booting");field("restricted").setBoolean(MeshMessengerAppLock,true)
            MeshMessengerAppLock.install(RuntimeEnvironment.getApplication())
            field("store").set(MeshMessengerAppLock,policy)
        } finally { release.countDown() }
        return worker.submit {}
    }
    @Test fun resumeCannotActivateWhileBootCleanupIsIncomplete() {
        configure("disabled")
        val rootField=MeshMessengerProtectedFiles::class.java.getDeclaredField("root").apply { isAccessible=true }
        val original=rootField.get(MeshMessengerProtectedFiles) as File
        val entered=CountDownLatch(1);val release=CountDownLatch(1)
        rootField.set(MeshMessengerProtectedFiles,object:File(original.path) {
            override fun listFiles(): Array<File> { entered.countDown();check(release.await(5,TimeUnit.SECONDS));return emptyArray() }
        })
        var boot: Future<*>?=null
        try {
            boot=beginReboot();waitFor { entered.count==0L }
            activity.pause().resume();settle();field("ownedForeground").setBoolean(MeshMessengerAppLock,true)
            val expected=MeshMessengerAppLock.currentEpoch()
            assertThrows(IllegalStateException::class.java) { MeshMessengerAppLock.activate(expected) }
            assertNotEquals("disabled",MeshMessengerAppLock.state()["phase"])
        } finally { release.countDown();boot?.get(5,TimeUnit.SECONDS);rootField.set(MeshMessengerProtectedFiles,original) }
    }
    @Test fun manualLockDuringInitialPolicyReadSurvivesDisabledBootstrap() {
        configure("disabled");val entered=CountDownLatch(1);val release=CountDownLatch(1)
        policy.beforeLoad={ entered.countDown();check(release.await(5,TimeUnit.SECONDS)) }
        val boot=beginReboot()
        try { waitFor { entered.count==0L };MeshMessengerAppLock.lock() }
        finally { release.countDown();boot.get(5,TimeUnit.SECONDS);policy.beforeLoad=null }
        assertEquals("locked",MeshMessengerAppLock.state()["phase"])
    }
    @Test fun clipboardPublicationAndRevokeHaveOneNativeOrdering() {
        val (future,request)=start();approve(request);future.get(5,TimeUnit.SECONDS);settle()
        val expected=MeshMessengerAppLock.currentEpoch();val revoked=CountDownLatch(1);var revoke:Future<*>?=null
        ClipboardOS.beforeSet={
            revoke=executor.submit { MeshMessengerAppLock.lock();revoked.countDown() }
            assertFalse("revoke completed inside an admitted OS clipboard publication",revoked.await(100,TimeUnit.MILLISECONDS))
        }
        try { MeshMessengerAppLock.copyProtectedText("owned test copy",expected) }
        finally { ClipboardOS.beforeSet=null;revoke?.get(5,TimeUnit.SECONDS) }
        val clipboard=RuntimeEnvironment.getApplication().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        assertEquals("owned test copy",clipboard.primaryClip!!.getItemAt(0).text.toString())
        assertThrows(IllegalStateException::class.java) { MeshMessengerAppLock.copyProtectedText("stale",expected) }
        assertEquals("owned test copy",clipboard.primaryClip!!.getItemAt(0).text.toString())
    }
    @Test fun queuedClipboardCannotRefreshAfterNewUnlock() {
        val clipboard=RuntimeEnvironment.getApplication().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("user prior copy","preserved"))
        val (first,request)=start();approve(request);first.get(5,TimeUnit.SECONDS);settle()
        val expected=MeshMessengerAppLock.currentEpoch();val queued={ MeshMessengerAppLock.copyProtectedText("late",expected) }
        MeshMessengerAppLock.lock();settle();val (next,owned)=start();approve(owned);next.get(5,TimeUnit.SECONDS);settle()
        assertThrows(IllegalStateException::class.java) { queued() }
        assertEquals("preserved",clipboard.primaryClip!!.getItemAt(0).text.toString())
    }
    @Test fun manualLockDuringDisabledBootstrapDrainsLegacyPrivateNotices() {
        configure("disabled")
        val context=RuntimeEnvironment.getApplication()
        val manager=context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val tag="owned-preboot-private-notice";val id=731
        manager.createNotificationChannel(NotificationChannel("owned-preboot", "Owned fixture", NotificationManager.IMPORTANCE_DEFAULT))
        manager.notify(tag,id,Notification.Builder(context,"owned-preboot")
            .setSmallIcon(android.R.drawable.ic_dialog_info).setContentTitle("Owned legacy fixture").build())
        fun retained()=manager.activeNotifications.count { it.tag==tag && it.id==id }
        assertEquals(1,retained())
        val entered=CountDownLatch(1);val release=CountDownLatch(1)
        policy.beforeLoad={ entered.countDown();check(release.await(5,TimeUnit.SECONDS)) }
        var boot:Future<*>?=null
        try {
            boot=beginReboot();waitFor { entered.count==0L };MeshMessengerAppLock.lock()
            release.countDown();boot.get(5,TimeUnit.SECONDS);policy.beforeLoad=null
            assertEquals("locked",MeshMessengerAppLock.state()["phase"])
            assertEquals("effective preboot restriction must drain the real retained OS notification",0,retained())
        } finally {
            release.countDown();boot?.get(5,TimeUnit.SECONDS);policy.beforeLoad=null;manager.cancel(tag,id)
        }
    }

    private val noticeScope="chat/"+"a".repeat(32)
    private val secondNoticeScope="group/"+"b".repeat(64)
    private fun noticeMode() { MeshMessengerAppLock.accountChanging();configure("disabled");MeshMessengerAppLock.consumeInbox(MeshMessengerAppLock.currentEpoch()) }
    private fun noticeManager()=RuntimeEnvironment.getApplication().getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    private fun issueNotice(scope: String=noticeScope): String {
        val context=RuntimeEnvironment.getApplication()
        noticeManager().createNotificationChannel(NotificationChannel("owned-broker", "Owned broker fixture", NotificationManager.IMPORTANCE_DEFAULT))
        return MeshMessengerAppLock.publishNativeNotice(MeshMessengerAppLock.currentEpoch(),scope) { id ->
            noticeManager().notify(id,0,Notification.Builder(context,"owned-broker").setSmallIcon(android.R.drawable.ic_dialog_info).setContentTitle("Owned notice").build())
        }
    }
    private fun consumeNotice()=MeshMessengerAppLock.consumeNotificationIntent(MeshMessengerAppLock.currentEpoch(),activity.get())
    @Test fun noticeCurrentNativeIssuanceRoutesOnceAndGenericCompatibilityCannotStealIt() {
        noticeMode();val id=issueNotice()
        assertEquals(1,noticeManager().activeNotifications.count { it.tag==id })
        MeshMessengerAppLock.receiveNativeNotice(id,activity.get())
        assertFalse(MeshMessengerAppLock.consumeInbox(MeshMessengerAppLock.currentEpoch()))
        assertEquals("{\"version\":1,\"kind\":\"scope\",\"scope\":\"$noticeScope\"}",consumeNotice())
        assertEquals("{\"version\":1,\"kind\":\"none\"}",consumeNotice())
        MeshMessengerAppLock.receiveNativeNotice(id,activity.get())
        assertEquals("{\"version\":1,\"kind\":\"none\"}",consumeNotice())
    }
    @Test fun noticeDuplicateUsedIdentifierCannotReplaceANewerTap() {
        noticeMode();val first=issueNotice();val second=issueNotice(secondNoticeScope)
        MeshMessengerAppLock.receiveNativeNotice(first,activity.get());consumeNotice()
        MeshMessengerAppLock.receiveNativeNotice(second,activity.get())
        MeshMessengerAppLock.receiveNativeNotice(first,activity.get())
        assertEquals("{\"version\":1,\"kind\":\"scope\",\"scope\":\"$secondNoticeScope\"}",consumeNotice())
    }
    @Test fun noticeEpochAccountOwnerAndRecordChangesCannotRetainPrivateRoutes() {
        for(change in listOf("epoch","account","owner","record")) {
            noticeMode();val id=issueNotice();MeshMessengerAppLock.receiveNativeNotice(id,activity.get())
            when(change) {
                "epoch" -> MeshMessengerAppLock.invalidate("owned_test")
                "account" -> MeshMessengerAppLock.accountChanging()
                "owner" -> field("owner").set(MeshMessengerAppLock,WeakReference(Activity()))
                "record" -> field("record").set(MeshMessengerAppLock,policy.value.copy(sequence=1))
            }
            if(change=="owner") {
                assertThrows(IllegalStateException::class.java) { consumeNotice() }
                field("owner").set(MeshMessengerAppLock,WeakReference(activity.get()))
                // Native wrong-owner delivery must never preserve private authority.
                MeshMessengerAppLock.receiveNativeNotice(id,Activity())
            }
            assertEquals("$change must downgrade the old route","{\"version\":1,\"kind\":\"inbox\"}",consumeNotice())
            assertEquals("{\"version\":1,\"kind\":\"none\"}",consumeNotice())
        }
    }
    @Test fun noticeCapacityIncludesConsumedTombstonesAndRefusesBeforeOSPublication() {
        noticeMode()
        repeat(128) { val id=issueNotice();MeshMessengerAppLock.receiveNativeNotice(id,activity.get());consumeNotice() }
        var posted=false
        assertThrows(IllegalStateException::class.java) {
            MeshMessengerAppLock.publishNativeNotice(MeshMessengerAppLock.currentEpoch(),noticeScope) { posted=true }
        }
        assertFalse("capacity refusal must precede OS publication",posted)
    }
    @Test fun noticeFailedPostAndExactCleanupCannotDeleteALaterPendingRoute() {
        noticeMode();var failed=""
        assertThrows(IllegalArgumentException::class.java) {
            MeshMessengerAppLock.publishNativeNotice(MeshMessengerAppLock.currentEpoch(),noticeScope) { failed=it;throw IllegalArgumentException("owned_post_failure") }
        }
        val later=issueNotice(secondNoticeScope);MeshMessengerAppLock.receiveNativeNotice(later,activity.get())
        MeshMessengerAppLock.forgetNativeNotice(failed)
        assertEquals("{\"version\":1,\"kind\":\"scope\",\"scope\":\"$secondNoticeScope\"}",consumeNotice())
        MeshMessengerAppLock.receiveNativeNotice(failed,activity.get())
        assertEquals("{\"version\":1,\"kind\":\"inbox\"}",consumeNotice())
    }
    @Test fun noticePublicationAndCompletedRevocationHaveOneNativeOrdering() {
        noticeMode();val expected=MeshMessengerAppLock.currentEpoch();val revoked=CountDownLatch(1);var future:Future<*>?=null
        val id=try {
            MeshMessengerAppLock.publishNativeNotice(expected,noticeScope) {
                future=executor.submit { MeshMessengerAppLock.accountChanging();revoked.countDown() }
                assertFalse("revoke completed inside admitted OS notice post",revoked.await(100,TimeUnit.MILLISECONDS))
            }
        } finally { future?.get(5,TimeUnit.SECONDS) }
        assertThrows(IllegalStateException::class.java) { MeshMessengerAppLock.publishNativeNotice(expected,noticeScope) { fail("stale post") } }
        MeshMessengerAppLock.receiveNativeNotice(id,activity.get())
        assertEquals("{\"version\":1,\"kind\":\"inbox\"}",consumeNotice())
    }
    @Test fun noticeUnknownColdIdentifiersStayGenericAndInvalidScopesNeverPublish() {
        noticeMode();MeshMessengerAppLock.receiveNativeNotice(UUID.randomUUID().toString(),activity.get())
        assertEquals("{\"version\":1,\"kind\":\"inbox\"}",consumeNotice())
        for(scope in listOf("chat/private","chat/"+"A".repeat(32),"group/"+"a".repeat(63),"chat/"+"a".repeat(32)+"\n")) {
            var posted=false
            assertThrows(IllegalArgumentException::class.java) { MeshMessengerAppLock.publishNativeNotice(MeshMessengerAppLock.currentEpoch(),scope) { posted=true } }
            assertFalse(posted)
        }
    }

    @Test fun noticeOwnedIntentIsConsumedBeforeActualExpoLifecycleAndRoutesOnlyNativeIssuance() {
        noticeMode();val id=issueNotice()
        val intent=Intent("app.morse.mesh.NOTICE_OPEN").putExtra("app.morse.mesh.NOTICE_ID",id)
        MeshMessengerNotificationIntents.consumeBeforeReact(activity.get(),intent)
        assertNull("React must receive no private or response extras",intent.extras)
        expo.modules.notifications.service.delegates.ExpoNotificationLifecycleListener().onNewIntent(intent)
        assertEquals("{\"version\":1,\"kind\":\"scope\",\"scope\":\"$noticeScope\"}",consumeNotice())
        assertEquals("{\"version\":1,\"kind\":\"none\"}",consumeNotice())
    }
    @Test fun noticeFCMAndLegacyLaunchesCannotEnterActualExpoResponseCacheOnColdOrWarmPaths() {
        noticeMode();val received=mutableListOf<Bundle>()
        val observer=object:expo.modules.notifications.notifications.interfaces.NotificationListener {
            override fun onNotificationResponseIntentReceived(extras: Bundle): Boolean { received.add(Bundle(extras));return true }
        }
        val notices=expo.modules.notifications.notifications.NotificationManager
        val expo=expo.modules.notifications.service.delegates.ExpoNotificationLifecycleListener()
        val previous=activity.get().intent;notices.addListener(observer)
        try {
            for(key in listOf("google.message_id","notificationResponse","textInputNotificationResponse","app.morse.mesh.APP_LOCK_INBOX","app.morse.mesh.NOTICE_ID")) {
                for(cold in listOf(true,false)) {
                    val intent=Intent(Intent.ACTION_MAIN).putExtra(key,"owned-fixture-id").putExtra("private-body","owned-private-fixture")
                    MeshMessengerNotificationIntents.consumeBeforeReact(activity.get(),intent)
                    if(cold) { activity.get().intent=intent;expo.onCreate(activity.get(),null) } else expo.onNewIntent(intent)
                    assertTrue("$key must not reach Expo's actual listener or retained cache",received.isEmpty())
                    assertNull("all response extras removed before React",intent.extras)
                    assertEquals("{\"version\":1,\"kind\":\"inbox\"}",consumeNotice())
                }
            }
        } finally { activity.get().intent=previous;notices.removeListener(observer) }
    }
    @Test fun noticePendingIntentTargetsTheOwnedActivityDirectlyAndIsImmutableWithOpaqueExtrasOnly() {
        noticeMode();val id=UUID.randomUUID().toString()
        val pending=MeshMessengerNotificationIntents.forNotice(activity.get(),id)
        val shadow=shadowOf(pending);assertTrue(shadow.isActivity);assertTrue(shadow.isImmutable)
        val intent=shadow.savedIntent
        assertEquals(activity.get().javaClass.name,intent.component!!.className)
        assertEquals("app.morse.mesh.NOTICE_OPEN",intent.action)
        assertEquals(setOf("app.morse.mesh.NOTICE_ID"),intent.extras!!.keySet())
        assertEquals(id,intent.getStringExtra("app.morse.mesh.NOTICE_ID"))
        assertNotEquals(pending,MeshMessengerNotificationIntents.forNotice(activity.get(),UUID.randomUUID().toString()))
    }
    @Test fun noticeSanitizationPreservesOrdinaryNonNotificationLaunches() {
        noticeMode();val intent=Intent(Intent.ACTION_VIEW,android.net.Uri.parse("morse://ordinary-link"))
            .putExtra("ordinary","preserve this")
        MeshMessengerNotificationIntents.consumeBeforeReact(activity.get(),intent)
        assertEquals(Intent.ACTION_VIEW,intent.action);assertEquals("morse://ordinary-link",intent.dataString)
        assertEquals("preserve this",intent.getStringExtra("ordinary"))
        assertEquals("{\"version\":1,\"kind\":\"none\"}",consumeNotice())
    }

    @Test fun noticeFreshDisabledBackgroundIssuanceSurvivesWarmPreResumeTapButOldIssuanceDoesNot() {
        noticeMode();val old=issueNotice();val beforePause=MeshMessengerAppLock.currentEpoch()
        activity.pause();settle();assertNotEquals(beforePause,MeshMessengerAppLock.currentEpoch())
        try {
            val current=issueNotice()
            val intent=Intent("app.morse.mesh.NOTICE_OPEN").putExtra("app.morse.mesh.NOTICE_ID",current)
            MeshMessengerNotificationIntents.consumeBeforeReact(activity.get(),intent)
            assertNull(intent.extras)
            assertThrows(IllegalStateException::class.java) { consumeNotice() }
        } finally {
            activity.resume().visible();settle();field("ownedForeground").setBoolean(MeshMessengerAppLock,true)
        }
        assertEquals("{\"version\":1,\"kind\":\"scope\",\"scope\":\"$noticeScope\"}",consumeNotice())
        assertEquals("{\"version\":1,\"kind\":\"none\"}",consumeNotice())
        MeshMessengerAppLock.receiveNativeNotice(old,activity.get())
        assertEquals("{\"version\":1,\"kind\":\"inbox\"}",consumeNotice())
    }
    @Test fun noticeRestrictedOrDestroyedNativeOwnerCannotIssueOrRecoverPrivateRoutes() {
        noticeMode();val beforeLock=issueNotice();MeshMessengerAppLock.lock();settle()
        var posted=false
        assertThrows(IllegalStateException::class.java) {
            MeshMessengerAppLock.publishNativeNotice(MeshMessengerAppLock.currentEpoch(),noticeScope) { posted=true }
        }
        assertFalse(posted);MeshMessengerAppLock.receiveNativeNotice(beforeLock,activity.get())
        val (future,request)=start();approve(request);future.get(5,TimeUnit.SECONDS);settle()
        assertEquals("{\"version\":1,\"kind\":\"inbox\"}",consumeNotice())
        val beforeDestroy=issueNotice();val oldOwner=activity.get()
        activity.pause().stop().destroy();settle()
        try {
            assertThrows(IllegalStateException::class.java) {
                MeshMessengerAppLock.publishNativeNotice(MeshMessengerAppLock.currentEpoch(),noticeScope) { posted=true }
            }
            assertFalse(posted);MeshMessengerAppLock.receiveNativeNotice(beforeDestroy,oldOwner)
        } finally {
            activity=Robolectric.buildActivity(Owner::class.java).create().start().resume().visible();settle();configure("disabled")
        }
        assertEquals("{\"version\":1,\"kind\":\"inbox\"}",consumeNotice())
    }

    private fun publisherManager(): NotificationManager {
        val app: Application=RuntimeEnvironment.getApplication()
        app.applicationInfo.icon=android.R.drawable.sym_def_app_icon
        val resolve=android.content.pm.ResolveInfo().apply {
            activityInfo=android.content.pm.ActivityInfo().apply {
                packageName=app.packageName;name=Owner::class.java.name;applicationInfo=app.applicationInfo
            }
        }
        for(category in listOf(Intent.CATEGORY_INFO,Intent.CATEGORY_LAUNCHER)) {
            shadowOf(app.packageManager).addResolveInfoForIntent(Intent(Intent.ACTION_MAIN).addCategory(category).setPackage(app.packageName),resolve)
        }
        return (app.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).also {
            it.cancelAll();it.createNotificationChannel(NotificationChannel("messages","Messages and mentions",NotificationManager.IMPORTANCE_HIGH))
        }
    }
    private fun publisherFrame(scope: String=noticeScope): String = org.json.JSONObject(mapOf(
        "version" to 1,"id" to "private-message-dedup-id","title" to "Private sender",
        "body" to "Private message body","scope" to scope,"mention" to false)).toString()
    @Test fun actualMessagePublisherUsesOnlyOpaqueNativeTapAndNoExpoRequestExtras() {
        noticeMode();val manager=publisherManager()
        MeshMessengerLockedNotifications.publish(publisherFrame(),MeshMessengerAppLock.currentEpoch())
        val posted=manager.activeNotifications.single();val notification=posted.notification
        assertEquals("Private sender",notification.extras.getCharSequence(Notification.EXTRA_TITLE).toString())
        assertEquals("Private message body",notification.extras.getCharSequence(Notification.EXTRA_TEXT).toString())
        assertEquals("messages",notification.channelId);assertEquals(Notification.VISIBILITY_PRIVATE,notification.visibility)
        assertFalse(notification.extras.containsKey("expo.notification_request"));assertFalse(notification.extras.containsKey("body"))
        val pending=shadowOf(notification.contentIntent);assertTrue(pending.isActivity);assertTrue(pending.isImmutable)
        val launch=pending.savedIntent
        assertEquals(Owner::class.java.name,launch.component?.className)
        assertEquals(setOf("app.morse.mesh.NOTICE_ID"),launch.extras!!.keySet())
        val id=launch.getStringExtra("app.morse.mesh.NOTICE_ID")!!
        assertEquals(UUID.fromString(id).toString(),id);assertEquals(id,posted.tag)
        assertFalse(launch.toUri(0).contains("Private"));assertFalse(launch.toUri(0).contains(noticeScope))
        MeshMessengerNotificationIntents.consumeBeforeReact(activity.get(),launch)
        assertEquals("{\"version\":1,\"kind\":\"scope\",\"scope\":\"$noticeScope\"}",consumeNotice())
        assertEquals("{\"version\":1,\"kind\":\"none\"}",consumeNotice())
    }
    @Test fun actualMessagePublisherRetainsFreshBackgroundScopeAndRejectsStaleCallerBeforePost() {
        noticeMode();val manager=publisherManager();val old=MeshMessengerAppLock.currentEpoch()
        activity.pause();settle()
        try {
            assertThrows(IllegalStateException::class.java) { MeshMessengerLockedNotifications.publish(publisherFrame(),old) }
            assertTrue(manager.activeNotifications.isEmpty())
            MeshMessengerLockedNotifications.publish(publisherFrame(),MeshMessengerAppLock.currentEpoch())
            val launch=shadowOf(manager.activeNotifications.single().notification.contentIntent).savedIntent
            MeshMessengerNotificationIntents.consumeBeforeReact(activity.get(),launch)
            assertThrows(IllegalStateException::class.java) { consumeNotice() }
        } finally {
            activity.resume().visible();settle();field("ownedForeground").setBoolean(MeshMessengerAppLock,true)
        }
        assertEquals("{\"version\":1,\"kind\":\"scope\",\"scope\":\"$noticeScope\"}",consumeNotice())
    }
    @Test fun actualMessagePublisherRejectsMalformedScopeBeforeAnyOSPublication() {
        noticeMode();val manager=publisherManager()
        for(scope in listOf("private-route", "chat/"+"A".repeat(32), "group/"+"a".repeat(65))) {
            assertThrows(IllegalArgumentException::class.java) { MeshMessengerLockedNotifications.publish(publisherFrame(scope),MeshMessengerAppLock.currentEpoch()) }
            assertTrue(manager.activeNotifications.isEmpty())
        }
    }
    @Test fun actualMessagePublisherEnabledPolicyDisplaysOnlyGenericContentEvenAfterUnlock() {
        noticeMode();val manager=publisherManager();val (future,request)=start(true);approve(request)
        future.get(5,TimeUnit.SECONDS);settle();field("ownedForeground").setBoolean(MeshMessengerAppLock,true)
        MeshMessengerLockedNotifications.publish(publisherFrame(),MeshMessengerAppLock.currentEpoch())
        val notification=manager.activeNotifications.single().notification
        assertEquals("New encrypted activity",notification.extras.getCharSequence(Notification.EXTRA_TEXT).toString())
        assertFalse(notification.extras.containsKey("expo.notification_request"));assertFalse(notification.extras.toString().contains("Private"))
        MeshMessengerNotificationIntents.consumeBeforeReact(activity.get(),shadowOf(notification.contentIntent).savedIntent)
        assertEquals("{\"version\":1,\"kind\":\"inbox\"}",consumeNotice())
    }

    class ObservedFirebaseService : MeshMessengerFirebaseMessagingService() {
        val received=mutableListOf<com.google.firebase.messaging.RemoteMessage>()
        val tokens=mutableListOf<String>()
        var deleted=0
        override val firebaseMessagingDelegate=object : expo.modules.notifications.service.interfaces.FirebaseMessagingDelegate {
            override fun onMessageReceived(message: com.google.firebase.messaging.RemoteMessage) { received.add(message) }
            override fun onNewToken(token: String) { tokens.add(token) }
            override fun onDeletedMessages() { deleted+=1 }
        }
    }
    private fun hostileRemote(notification: Boolean=false): Bundle = Bundle().apply {
        putString("google.message_id",UUID.randomUUID().toString());putInt("google.product_id",123)
        putString("from","private-sender");putString("collapse_key","private-conversation")
        putString("to","private-recipient");putString("title","Private sender")
        putString("message","Private message");putString("scope",noticeScope)
        putString("body","{\"scope\":\"$noticeScope\",\"text\":\"Private plaintext\"}")
        putString("dataString","Private old serialized payload");putString("google.c.a.e","1")
        if(notification) {
            putString("gcm.n.e","1");putString("gcm.n.title","Private FCM sender")
            putString("gcm.n.body","Private FCM message");putString("gcm.n.tag","private-tag")
            putString("gcm.n.android_channel_id","messages")
        }
    }
    private fun assertGenericRemote(message: com.google.firebase.messaging.RemoteMessage,alert: Boolean) {
        val wake="{\"kind\":\"encrypted-wakeup\"}"
        val expected=if(alert) mapOf("body" to wake,"message" to "New encrypted activity") else mapOf("body" to wake)
        assertEquals(expected,message.data);assertNull(message.notification)
        assertNull(message.messageId);assertNull(message.from);assertNull(message.to);assertNull(message.collapseKey)
        // These are the installed Expo foreground and TaskManager serializers.
        val content=expo.modules.notifications.notifications.model.RemoteNotificationContent(message)
        assertNull(content.title);assertEquals(if(alert)"New encrypted activity" else null,content.text)
        assertEquals(setOf("kind"),content.body!!.keys().asSequence().toSet())
        assertEquals("encrypted-wakeup",content.body!!.getString("kind"))
        val bundle=expo.modules.notifications.notifications.RemoteMessageSerializer.toBundle(message)
        assertNull(bundle.getBundle("notification"));assertNull(bundle.getString("messageId"))
        val data=bundle.getBundle("data")!!
        assertEquals(expected.keys+"dataString",data.keySet());assertEquals(wake,data.getString("dataString"))
    }
    @Test fun remoteCallbackReplacesPrivateNotificationBeforeAnyExpoDelegateOrSerialization() {
        val controller=Robolectric.buildService(ObservedFirebaseService::class.java).create()
        try {
            val source=hostileRemote(true);val original=com.google.firebase.messaging.RemoteMessage(source)
            controller.get().onMessageReceived(original)
            assertEquals("Private FCM message",original.notification!!.body)
            assertGenericRemote(controller.get().received.single(),true)
        } finally { controller.destroy() }
    }
    @Test fun firebaseSDKNotificationIntentCannotAutoDisplayPrivatePayloadBeforeCallback() {
        val manager=publisherManager()
        val keyguard=RuntimeEnvironment.getApplication().getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        shadowOf(keyguard).setInRestrictedInputMode(true);assertTrue(keyguard.inKeyguardRestrictedInputMode())
        val controller=Robolectric.buildService(ObservedFirebaseService::class.java).create()
        try {
            val input=Intent("com.google.android.c2dm.intent.RECEIVE").putExtras(hostileRemote(true))
            controller.get().handleIntent(input)
            assertTrue("actual Firebase pre-callback path posted private notification",manager.activeNotifications.isEmpty())
            assertEquals("Private FCM message",input.getStringExtra("gcm.n.body"))
            assertGenericRemote(controller.get().received.single(),true)
        } finally { controller.destroy() }
    }
    @Test fun firebaseDataIngressKeepsNativeDedupButDropsTransportAndPrivateFieldsBeforeExpo() {
        val controller=Robolectric.buildService(ObservedFirebaseService::class.java).create()
        try {
            val input=Intent("com.google.android.c2dm.intent.RECEIVE").putExtras(hostileRemote())
            controller.get().handleIntent(input);controller.get().handleIntent(input)
            assertEquals(1,controller.get().received.size)
            assertGenericRemote(controller.get().received.single(),false)
            val alert=Intent("com.google.android.c2dm.intent.RECEIVE").putExtras(hostileRemote()).putExtra("message","New encrypted activity")
            controller.get().handleIntent(alert)
            assertEquals(2,controller.get().received.size);assertGenericRemote(controller.get().received.last(),true)
        } finally { controller.destroy() }
    }
    @Test fun firebaseDirectBootAndLegacyNotificationPrefixAreSanitizedBeforeSDK() {
        val manager=publisherManager()
        val keyguard=RuntimeEnvironment.getApplication().getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        shadowOf(keyguard).setInRestrictedInputMode(true);assertTrue(keyguard.inKeyguardRestrictedInputMode())
        val controller=Robolectric.buildService(ObservedFirebaseService::class.java).create()
        try {
            val input=Intent("com.google.firebase.messaging.RECEIVE_DIRECT_BOOT").putExtras(hostileRemote()).apply {
                putExtra("gcm.notification.e","1");putExtra("gcm.notification.title","Private legacy title")
                putExtra("gcm.notification.body","Private legacy message")
            }
            controller.get().handleIntent(input)
            assertTrue("legacy FCM auto-display escaped ingress",manager.activeNotifications.isEmpty())
            assertGenericRemote(controller.get().received.single(),true)
        } finally { controller.destroy() }
    }
    @Test fun firebaseNativeTokenAndDroppedMessageCallbacksRemainFunctional() {
        val controller=Robolectric.buildService(ObservedFirebaseService::class.java).create()
        try {
            controller.get().handleIntent(Intent("com.google.firebase.messaging.NEW_TOKEN").putExtra("token","owned-native-token"))
            controller.get().handleIntent(Intent("com.google.android.c2dm.intent.RECEIVE").putExtra("google.message_id",UUID.randomUUID().toString()).putExtra("message_type","deleted_messages"))
            assertEquals(listOf("owned-native-token"),controller.get().tokens)
            assertEquals(1,controller.get().deleted);assertTrue(controller.get().received.isEmpty())
        } finally { controller.destroy() }
    }

    @Implements(value=NotificationManager::class)
    class DelegationOS : org.robolectric.shadows.ShadowNotificationManager() {
        companion object { var refuseRemoval=false }
        @Implementation protected override fun setNotificationDelegate(delegate: String?) {
            if(delegate!=null || !refuseRemoval) super.setNotificationDelegate(delegate)
        }
    }
    @Test @Config(sdk=[35])
    fun existingOSNotificationDelegateIsRemovedBeforeDisabledBootCanReadPolicyOrAdmitWork() {
        configure("disabled")
        val manager=noticeManager();manager.setNotificationDelegate("com.google.android.gms")
        assertEquals("com.google.android.gms",manager.notificationDelegate)
        var read=false
        policy.beforeLoad={ assertNull("delegation must be revoked before native boot policy read",manager.notificationDelegate);read=true }
        try {
            beginReboot().get(5,TimeUnit.SECONDS);settle()
            assertNull(manager.notificationDelegate);assertTrue(read)
            assertEquals("disabled",MeshMessengerAppLock.state()["phase"])
            MeshMessengerAppLock.requireEpoch(MeshMessengerAppLock.currentEpoch())
        } finally { policy.beforeLoad=null;manager.setNotificationDelegate(null) }
    }
    @Test @Config(sdk=[35],shadows=[DelegationOS::class])
    fun OSRefusalToRemoveNotificationDelegatePreventsBootAdmission() {
        configure("disabled")
        val manager=noticeManager();manager.setNotificationDelegate("com.google.android.gms")
        assertEquals("com.google.android.gms",manager.notificationDelegate)
        var read=false;policy.beforeLoad={ read=true };DelegationOS.refuseRemoval=true
        try {
            beginReboot().get(5,TimeUnit.SECONDS);settle()
            assertEquals("error",MeshMessengerAppLock.state()["phase"])
            assertFalse("do not continue bootstrap after failed native delegation readback",read)
            assertThrows(IllegalStateException::class.java) { MeshMessengerAppLock.requireEpoch(MeshMessengerAppLock.currentEpoch()) }
        } finally { DelegationOS.refuseRemoval=false;policy.beforeLoad=null;manager.setNotificationDelegate(null) }
    }

    @Test fun freshDisabledHeadlessMessagePublishesGenericAndNeverRetainsPrivateRoute() {
        noticeMode();val manager=publisherManager();var launch:Intent?=null
        // Real native owner destruction, followed by a fresh admitted headless
        // action. Do not fabricate an Activity or reuse its pre-destroy epoch.
        activity.pause().stop().destroy();settle()
        try {
            assertThrows(IllegalStateException::class.java) { MeshMessengerAppLock.currentActivity() }
            val expected=MeshMessengerAppLock.currentEpoch();MeshMessengerAppLock.requireEpoch(expected)
            MeshMessengerLockedNotifications.publish(publisherFrame(),expected)
            val posted=manager.activeNotifications.single().notification
            assertEquals("New encrypted activity",posted.extras.getCharSequence(Notification.EXTRA_TEXT).toString())
            assertFalse(posted.extras.toString().contains("Private"));assertFalse(posted.extras.containsKey("expo.notification_request"))
            launch=shadowOf(posted.contentIntent).savedIntent
            assertFalse(launch!!.toUri(0).contains(noticeScope));assertFalse(launch!!.hasExtra("app.morse.mesh.NOTICE_ID"))
        } finally {
            activity=Robolectric.buildActivity(Owner::class.java).create().start().resume().visible();settle()
            field("ownedForeground").setBoolean(MeshMessengerAppLock,true)
        }
        MeshMessengerNotificationIntents.consumeBeforeReact(activity.get(),requireNotNull(launch))
        assertEquals("{\"version\":1,\"kind\":\"inbox\"}",consumeNotice())
        assertEquals("{\"version\":1,\"kind\":\"none\"}",consumeNotice())
    }

    private fun legacyPrivateNotice() = expo.modules.notifications.notifications.model.Notification(
        expo.modules.notifications.notifications.model.NotificationRequest("legacy-private-message-id",
            expo.modules.notifications.notifications.model.NotificationContent.Builder()
                .setTitle("Private legacy sender").setText("Private legacy body")
                .setBody(org.json.JSONObject(mapOf("scope" to noticeScope,"messageId" to "private-legacy-id")))
                .build(),null))

    @Test fun legacyResponseReceiverNeverFeedsPrivateResponseToActualExpoEvenWhenDisabled() {
        noticeMode();publisherManager()
        val app:Application=RuntimeEnvironment.getApplication()
        val responses=mutableListOf<expo.modules.notifications.notifications.model.NotificationResponse>()
        val observer=object:expo.modules.notifications.notifications.interfaces.NotificationListener {
            override fun onNotificationResponseReceived(response:expo.modules.notifications.notifications.model.NotificationResponse):Boolean {
                responses.add(response);return true
            }
        }
        val notices=expo.modules.notifications.notifications.NotificationManager;notices.addListener(observer)
        try {
            val intent=Intent().putExtra("notification",legacyPrivateNotice()).putExtra("notificationAction",
                expo.modules.notifications.notifications.model.NotificationAction(
                    expo.modules.notifications.notifications.model.NotificationResponse.DEFAULT_ACTION_IDENTIFIER,"Open",true) as android.os.Parcelable)
            MeshMessengerNotificationsService().onReceiveNotificationResponse(app,intent)
            assertTrue("legacy response must bypass actual Expo listener/cache",responses.isEmpty())
            val launch=requireNotNull(shadowOf(app).nextStartedActivity)
            assertNotNull(launch);assertNull(launch.extras)
            assertFalse(launch.toUri(0).contains("Private"));assertFalse(launch.toUri(0).contains(noticeScope))
            assertEquals("{\"version\":1,\"kind\":\"inbox\"}",consumeNotice())
            assertEquals("{\"version\":1,\"kind\":\"none\"}",consumeNotice())
        } finally { notices.removeListener(observer) }
    }

    @Test fun legacyPresentationCannotSerializePrivateExpoRequestsIntoOSNotifications() {
        noticeMode();val manager=publisherManager()
        val app:Application=RuntimeEnvironment.getApplication()
        MeshMessengerNotificationsService().onPresentNotification(app,Intent()
            .putExtra("notification",legacyPrivateNotice())
            .putExtra("notificationBehavior",expo.modules.notifications.notifications.model.NotificationBehaviorRecord.ALLOW_ALL))
        val notice=manager.activeNotifications.single().notification
        assertEquals("New encrypted activity",notice.extras.getCharSequence(Notification.EXTRA_TEXT).toString())
        assertFalse(notice.extras.containsKey("expo.notification_request"))
        val launch=shadowOf(notice.contentIntent).savedIntent
        assertFalse(launch.toUri(0).contains("Private"));assertFalse(launch.toUri(0).contains(noticeScope))
        assertFalse(launch.hasExtra("notificationResponse"));assertFalse(launch.hasExtra("notification"))
    }

    @Test fun legacySchedulingDoesNotPersistPrivateContentOrArmANewAlarm() {
        noticeMode();publisherManager()
        val app:Application=RuntimeEnvironment.getApplication()
        val prefs=app.getSharedPreferences("expo.modules.notifications.SharedPreferencesNotificationsStore",Context.MODE_PRIVATE)
        val alarm=shadowOf(app.getSystemService(Context.ALARM_SERVICE) as android.app.AlarmManager)
        val previous=alarm.scheduledAlarms.size
        val request=expo.modules.notifications.notifications.model.NotificationRequest("legacy-private-message-id",
            legacyPrivateNotice().notificationRequest.content,
            expo.modules.notifications.notifications.triggers.DateTrigger("messages",System.currentTimeMillis()+60_000))
        try {
            MeshMessengerNotificationsService().onScheduleNotification(app,Intent().putExtra("notificationRequest",request as android.os.Parcelable))
            assertTrue("legacy schedules must not retain serialized private history",prefs.all.isEmpty())
            assertEquals(previous,alarm.scheduledAlarms.size)
        } finally { prefs.edit().clear().commit() }
    }

    @Test fun legacyReceiptReplacesPrivateContentBeforeActualExpoForegroundDelivery() {
        noticeMode();publisherManager()
        val app:Application=RuntimeEnvironment.getApplication()
        val lifecycleOwner=Class.forName("androidx.lifecycle.ProcessLifecycleOwner").getMethod("get").invoke(null) as androidx.lifecycle.LifecycleOwner
        val lifecycle=lifecycleOwner.lifecycle as androidx.lifecycle.LifecycleRegistry
        lifecycle.currentState=androidx.lifecycle.Lifecycle.State.RESUMED
        val received=mutableListOf<expo.modules.notifications.notifications.model.Notification>()
        val observer=object:expo.modules.notifications.notifications.interfaces.NotificationListener {
            override fun onNotificationReceived(notification:expo.modules.notifications.notifications.model.Notification) { received.add(notification) }
        }
        val notices=expo.modules.notifications.notifications.NotificationManager;notices.addListener(observer)
        try {
            MeshMessengerNotificationsService().onReceiveNotification(app,Intent().putExtra("notification",legacyPrivateNotice()))
            val delivered=received.single();val content=delivered.notificationRequest.content;val body=requireNotNull(content.body)
            assertEquals("New encrypted activity",content.text)
            assertEquals(setOf("kind"),body.keys().asSequence().toSet())
            assertEquals("encrypted-wakeup",body.getString("kind"))
            assertNotEquals("legacy-private-message-id",delivered.notificationRequest.identifier)
            val serialized=expo.modules.notifications.notifications.NotificationSerializer.toBundle(delivered)
            assertFalse(serialized.toString().contains("Private"));assertFalse(serialized.toString().contains(noticeScope))
        } finally { notices.removeListener(observer);lifecycle.currentState=androidx.lifecycle.Lifecycle.State.CREATED }
    }

    private fun moduleEvent(module: MeshMessengerModule, event: expo.modules.kotlin.events.EventName) {
        val callback=module.definition().eventListeners.getValue(event) as expo.modules.kotlin.events.BasicEventListener
        callback.call()
    }

    @Test fun destroyingAnUnregisteredModuleCannotRevokeTheActiveClient() {
        configure("disabled")
        val original=MeshMessengerAppLock.currentEpoch()
        MeshMessengerWalletStore.setActivity(activity.get())
        moduleEvent(MeshMessengerModule(),expo.modules.kotlin.events.EventName.MODULE_DESTROY)
        settle()
        assertEquals("unregistered teardown cannot revoke the active client",original,MeshMessengerAppLock.currentEpoch())
        MeshMessengerAppLock.requireEpoch(original)
        val wallet=MeshMessengerWalletStore::class.java.getDeclaredField("activity").apply { isAccessible=true }
        assertSame(activity.get(),(wallet.get(MeshMessengerWalletStore) as WeakReference<*>).get())
    }

    // This port supplies native host identity/lifecycle only. Expo AppContext,
    // registry, module definitions and callback bodies below are installed code.
    class NativeRuntimeApplication : Application(), com.facebook.react.ReactApplication {
        @Volatile var nativeHost: com.facebook.react.ReactHost? = null
        override val reactHost: com.facebook.react.ReactHost? get() = nativeHost
    }
    private class NativeHost(initial: com.facebook.react.bridge.ReactContext) {
        @Volatile var current: com.facebook.react.bridge.ReactContext? = initial
        val listeners = java.util.concurrent.CopyOnWriteArrayList<() -> Unit>()
        var onAdd: (() -> Unit)? = null
        val api = java.lang.reflect.Proxy.newProxyInstance(
            com.facebook.react.ReactHost::class.java.classLoader,
            arrayOf(com.facebook.react.ReactHost::class.java)
        ) { proxy, method, args ->
            when (method.name) {
                "getCurrentReactContext" -> current
                "addBeforeDestroyListener" -> {
                    @Suppress("UNCHECKED_CAST") val listener = args!![0] as () -> Unit
                    listeners.add(listener); onAdd?.invoke(); null
                }
                "removeBeforeDestroyListener" -> { listeners.remove(args!![0]); null }
                "getLifecycleState" -> com.facebook.react.common.LifecycleState.BEFORE_CREATE
                "equals" -> proxy === args!![0]
                "hashCode" -> System.identityHashCode(proxy)
                "toString" -> "TEST ONLY native ReactHost identity/lifecycle port"
                else -> error("unexpected_native_host_method:${method.name}")
            }
        } as com.facebook.react.ReactHost
        fun reset() { listeners.toList().forEach { it() }; current = null }
    }
    private val nativeHosts = java.util.IdentityHashMap<expo.modules.kotlin.AppContext,NativeHost>()
    private fun nativeHost(context: expo.modules.kotlin.AppContext) = nativeHosts.getValue(context)
    private fun nativeApplication() = (RuntimeEnvironment.getApplication() as NativeRuntimeApplication)
    private fun withActualModuleContext(body:(expo.modules.kotlin.AppContext)->Unit) {
        val react=com.facebook.react.bridge.BridgeReactContext(RuntimeEnvironment.getApplication())
        val provider=object:expo.modules.kotlin.ModulesProvider {
            override fun getModulesMap():Map<Class<out expo.modules.kotlin.modules.Module>,String?> = emptyMap()
        }
        val context=expo.modules.kotlin.AppContext(provider,expo.modules.core.ModuleRegistry(emptyList(),emptyList()),WeakReference(react))
        val host=NativeHost(react); val application=nativeApplication(); val previous=application.nativeHost
        nativeHosts[context]=host; application.nativeHost=host.api
        try { body(context) } finally {
            nativeHosts.remove(context)
            if (application.nativeHost === host.api) application.nativeHost=previous
            // No JSI runtime was installed. Release the real Expo host resources.
            (context.runtime.javaClass.getDeclaredField("deallocator").apply { isAccessible=true }.get(context.runtime) as AutoCloseable).close()
            context.modulesQueue.coroutineContext[kotlinx.coroutines.Job]?.cancel()
            context.mainQueue.coroutineContext[kotlinx.coroutines.Job]?.cancel()
            context.backgroundCoroutineScope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
            val dispatcher=context.javaClass.getDeclaredField("modulesQueueDispatcher").apply { isAccessible=true }.get(context)
            val handler=dispatcher.javaClass.getDeclaredField("handler").apply { isAccessible=true }.get(dispatcher) as android.os.Handler
            handler.looper.quitSafely()
        }
    }

    @Test fun oldActualModuleDestroyPreservesSuccessorInSameExpoContext() = withActualModuleContext { context ->
        configure("disabled")
        val old=MeshMessengerModule();context.registry.register(old,null)
        moduleEvent(old,expo.modules.kotlin.events.EventName.MODULE_CREATE)
        val fresh=MeshMessengerModule();context.registry.register(fresh,null)
        moduleEvent(fresh,expo.modules.kotlin.events.EventName.MODULE_CREATE)
        val expected=MeshMessengerAppLock.currentEpoch()
        MeshMessengerWalletStore.setActivity(activity.get())
        try {
            moduleEvent(old,expo.modules.kotlin.events.EventName.MODULE_DESTROY);settle()
            assertEquals("late old module destruction cannot revoke a successor",expected,MeshMessengerAppLock.currentEpoch())
            MeshMessengerAppLock.requireEpoch(expected)
            val wallet=MeshMessengerWalletStore::class.java.getDeclaredField("activity").apply { isAccessible=true }
            assertSame(activity.get(),(wallet.get(MeshMessengerWalletStore) as WeakReference<*>).get())
        } finally { moduleEvent(fresh,expo.modules.kotlin.events.EventName.MODULE_DESTROY) }
    }

    @Test fun currentActualModuleDestroyRevokesExactlyOnce() = withActualModuleContext { context ->
        configure("disabled")
        val current=MeshMessengerModule();context.registry.register(current,null)
        moduleEvent(current,expo.modules.kotlin.events.EventName.MODULE_CREATE)
        val admitted=MeshMessengerAppLock.currentEpoch()
        moduleEvent(current,expo.modules.kotlin.events.EventName.MODULE_DESTROY);settle()
        val revoked=MeshMessengerAppLock.currentEpoch()
        assertNotEquals(admitted,revoked)
        moduleEvent(current,expo.modules.kotlin.events.EventName.MODULE_DESTROY);settle()
        assertEquals("repeated teardown must not revoke another epoch",revoked,MeshMessengerAppLock.currentEpoch())
    }

    @Test fun replacementActualModuleRevokesPreviouslyCapturedEpoch() = withActualModuleContext { context ->
        configure("disabled")
        val old=MeshMessengerModule();context.registry.register(old,null)
        moduleEvent(old,expo.modules.kotlin.events.EventName.MODULE_CREATE)
        val previous=MeshMessengerAppLock.currentEpoch()
        val fresh=MeshMessengerModule();context.registry.register(fresh,null)
        moduleEvent(fresh,expo.modules.kotlin.events.EventName.MODULE_CREATE)
        try { assertNotEquals("module replacement must revoke old in-flight scope",previous,MeshMessengerAppLock.currentEpoch()) }
        finally { moduleEvent(old,expo.modules.kotlin.events.EventName.MODULE_DESTROY);moduleEvent(fresh,expo.modules.kotlin.events.EventName.MODULE_DESTROY) }
    }

    @Test fun oldActualModuleCannotUseSuccessorsScopeOrConsumeItsInbox() = withActualModuleContext { context ->
        configure("disabled")
        val old=MeshMessengerModule();context.registry.register(old,null)
        moduleEvent(old,expo.modules.kotlin.events.EventName.MODULE_CREATE)
        val fresh=MeshMessengerModule();context.registry.register(fresh,null)
        moduleEvent(fresh,expo.modules.kotlin.events.EventName.MODULE_CREATE)
        val expected=MeshMessengerAppLock.currentEpoch()
        MeshMessengerAppLock.recordInboxOpen()
        try {
            val failure=assertThrows(IllegalStateException::class.java) {
                old.definition().syncFunctions.getValue("checkAppLockScope").callUserImplementation(arrayOf(expected),context)
            }
            assertEquals("module_unavailable",failure.message)
            assertThrows(IllegalStateException::class.java) {
                old.definition().syncFunctions.getValue("consumeAppLockInboxIntent").callUserImplementation(arrayOf(expected),context)
            }
            fresh.definition().syncFunctions.getValue("checkAppLockScope").callUserImplementation(arrayOf(expected),context)
            assertEquals(true,fresh.definition().syncFunctions.getValue("consumeAppLockInboxIntent").callUserImplementation(arrayOf(expected),context))
        } finally { moduleEvent(old,expo.modules.kotlin.events.EventName.MODULE_DESTROY);moduleEvent(fresh,expo.modules.kotlin.events.EventName.MODULE_DESTROY) }
    }

    @Test fun oldActualModuleLifecycleCannotClearSuccessorsWalletOwner() = withActualModuleContext { context ->
        configure("disabled")
        val old=MeshMessengerModule();context.registry.register(old,null)
        moduleEvent(old,expo.modules.kotlin.events.EventName.MODULE_CREATE)
        val fresh=MeshMessengerModule();context.registry.register(fresh,null)
        moduleEvent(fresh,expo.modules.kotlin.events.EventName.MODULE_CREATE)
        MeshMessengerWalletStore.setActivity(activity.get())
        try {
            for(event in listOf(expo.modules.kotlin.events.EventName.ACTIVITY_ENTERS_BACKGROUND,expo.modules.kotlin.events.EventName.ACTIVITY_DESTROYS)) {
                moduleEvent(old,event)
                val wallet=MeshMessengerWalletStore::class.java.getDeclaredField("activity").apply { isAccessible=true }
                assertSame(activity.get(),(wallet.get(MeshMessengerWalletStore) as WeakReference<*>).get())
            }
        } finally { moduleEvent(old,expo.modules.kotlin.events.EventName.MODULE_DESTROY);moduleEvent(fresh,expo.modules.kotlin.events.EventName.MODULE_DESTROY) }
    }

    @Test fun delayedCreateFromOlderContextCannotReclaimTheNewerRegistration() = withActualModuleContext { oldContext ->
        configure("disabled")
        val old=MeshMessengerModule();oldContext.registry.register(old,null)
        moduleEvent(old,expo.modules.kotlin.events.EventName.MODULE_CREATE)
        withActualModuleContext { freshContext ->
            val fresh=MeshMessengerModule();freshContext.registry.register(fresh,null)
            moduleEvent(fresh,expo.modules.kotlin.events.EventName.MODULE_CREATE)
            val expected=MeshMessengerAppLock.currentEpoch()
            try {
                val failure=assertThrows(IllegalStateException::class.java) { moduleEvent(old,expo.modules.kotlin.events.EventName.MODULE_CREATE) }
                assertEquals("module_unavailable",failure.message)
                assertEquals(expected,MeshMessengerAppLock.currentEpoch())
                fresh.definition().syncFunctions.getValue("checkAppLockScope").callUserImplementation(arrayOf(expected),freshContext)
            } finally { moduleEvent(old,expo.modules.kotlin.events.EventName.MODULE_DESTROY);moduleEvent(fresh,expo.modules.kotlin.events.EventName.MODULE_DESTROY) }
        }
    }

    @Test fun createWithoutAnExpoRegistrationCannotInvalidateTheActiveModule() = withActualModuleContext { context ->
        configure("disabled")
        val current=MeshMessengerModule();context.registry.register(current,null)
        moduleEvent(current,expo.modules.kotlin.events.EventName.MODULE_CREATE)
        val expected=MeshMessengerAppLock.currentEpoch()
        try {
            assertThrows(RuntimeException::class.java) { moduleEvent(MeshMessengerModule(),expo.modules.kotlin.events.EventName.MODULE_CREATE) }
            assertEquals("validate actual native registration before changing authority",expected,MeshMessengerAppLock.currentEpoch())
            current.definition().syncFunctions.getValue("checkAppLockScope").callUserImplementation(arrayOf(expected),context)
        } finally { moduleEvent(current,expo.modules.kotlin.events.EventName.MODULE_DESTROY) }
    }

    @Test fun firstDelayedCreateFromOlderRuntimeCannotReplaceTheActiveRuntime() = withActualModuleContext { oldContext ->
        withActualModuleContext { freshContext ->
            configure("disabled")
            val old=MeshMessengerModule();oldContext.registry.register(old,null)
            val fresh=MeshMessengerModule();freshContext.registry.register(fresh,null)
            moduleEvent(fresh,expo.modules.kotlin.events.EventName.MODULE_CREATE)
            val expected=MeshMessengerAppLock.currentEpoch()
            try {
                val failure=assertThrows(IllegalStateException::class.java) { moduleEvent(old,expo.modules.kotlin.events.EventName.MODULE_CREATE) }
                assertEquals("module_unavailable",failure.message)
                assertEquals(expected,MeshMessengerAppLock.currentEpoch())
                fresh.definition().syncFunctions.getValue("checkAppLockScope").callUserImplementation(arrayOf(expected),freshContext)
            } finally { moduleEvent(old,expo.modules.kotlin.events.EventName.MODULE_DESTROY);moduleEvent(fresh,expo.modules.kotlin.events.EventName.MODULE_DESTROY) }
        }
    }

    private fun scope(module: MeshMessengerModule, context: expo.modules.kotlin.AppContext, expected: String) =
        module.definition().syncFunctions.getValue("checkAppLockScope").callUserImplementation(arrayOf(expected),context)

    @Test fun newlyConstructedModuleOnRetiredContextCannotClaimCurrentRuntime() = withActualModuleContext { oldContext ->
        withActualModuleContext { freshContext ->
            configure("disabled")
            val fresh=MeshMessengerModule(); freshContext.registry.register(fresh,null)
            moduleEvent(fresh,expo.modules.kotlin.events.EventName.MODULE_CREATE)
            val expected=MeshMessengerAppLock.currentEpoch()
            val late=MeshMessengerModule(); oldContext.registry.register(late,null)
            try {
                val failure=assertThrows(IllegalStateException::class.java) { moduleEvent(late,expo.modules.kotlin.events.EventName.MODULE_CREATE) }
                assertEquals("module_unavailable",failure.message)
                assertEquals("construction order must not replace actual native provenance",expected,MeshMessengerAppLock.currentEpoch())
                scope(fresh,freshContext,expected)
            } finally { moduleEvent(late,expo.modules.kotlin.events.EventName.MODULE_DESTROY); moduleEvent(fresh,expo.modules.kotlin.events.EventName.MODULE_DESTROY) }
        }
    }

    @Test fun missingOrMismatchedCanonicalHostRefusesBeforeAuthorityMutation() = withActualModuleContext { context ->
        configure("disabled")
        val application=nativeApplication(); val host=nativeHost(context); val expected=MeshMessengerAppLock.currentEpoch()
        for (missing in listOf(true,false)) {
            val module=MeshMessengerModule(); context.registry.register(module,null)
            application.nativeHost=if(missing)null else host.api
            if (!missing) host.current=com.facebook.react.bridge.BridgeReactContext(application)
            try {
                val failure=assertThrows(IllegalStateException::class.java) { moduleEvent(module,expo.modules.kotlin.events.EventName.MODULE_CREATE) }
                assertEquals("module_unavailable",failure.message)
                assertEquals("invalid host observations must not change authority",expected,MeshMessengerAppLock.currentEpoch())
            } finally { moduleEvent(module,expo.modules.kotlin.events.EventName.MODULE_DESTROY) }
        }
        application.nativeHost=host.api
    }

    @Test fun replacingApplicationHostRejectsSameContextScopeAndKeepsInboxPending() = withActualModuleContext { context ->
        configure("disabled")
        val module=MeshMessengerModule();context.registry.register(module,null)
        moduleEvent(module,expo.modules.kotlin.events.EventName.MODULE_CREATE)
        val expected=MeshMessengerAppLock.currentEpoch(); MeshMessengerAppLock.recordInboxOpen()
        val original=nativeHost(context);val replacement=NativeHost(requireNotNull(original.current))
        nativeApplication().nativeHost=replacement.api
        try {
            assertThrows(IllegalStateException::class.java) { scope(module,context,expected) }
            assertThrows(IllegalStateException::class.java) {
                module.definition().syncFunctions.getValue("consumeAppLockInboxIntent").callUserImplementation(arrayOf(expected),context)
            }
            assertTrue("unowned module must not consume queued inbox",MeshMessengerAppLock.consumeInbox(expected))
        } finally { nativeApplication().nativeHost=original.api;moduleEvent(module,expo.modules.kotlin.events.EventName.MODULE_DESTROY) }
    }

    @Test fun nativeHostResetDuringRegistrationCannotPublishReadyModule() = withActualModuleContext { context ->
        configure("disabled")
        val host=nativeHost(context);var reached=false
        host.onAdd={ reached=true;host.current=null }
        val module=MeshMessengerModule();context.registry.register(module,null)
        try {
            assertThrows(IllegalStateException::class.java) { moduleEvent(module,expo.modules.kotlin.events.EventName.MODULE_CREATE) }
            assertTrue("actual native listener-registration boundary reached",reached)
            assertTrue("failed registration must remove its native listener",host.listeners.isEmpty())
            assertThrows(IllegalStateException::class.java) { scope(module,context,MeshMessengerAppLock.currentEpoch()) }
        } finally { host.onAdd=null;moduleEvent(module,expo.modules.kotlin.events.EventName.MODULE_DESTROY) }
    }

    @Suppress("UNCHECKED_CAST")
    private fun suspendModuleCall(module: MeshMessengerModule, name: String, args: Array<out Any?>): Any? {
        val function=module.definition().asyncFunctions.getValue(name)
        val body=function.javaClass.getDeclaredField("body").apply { isAccessible=true }.get(function)
            as (suspend kotlinx.coroutines.CoroutineScope.(Array<out Any?>) -> Any?)
        return kotlinx.coroutines.runBlocking { body.invoke(this,args) }
    }

    @Test fun nativeBeforeDestroyRevokesAndRefusesActualInflightModuleAuthentication() = withActualModuleContext { context ->
        configure("enabled")
        val module=MeshMessengerModule();context.registry.register(module,null)
        moduleEvent(module,expo.modules.kotlin.events.EventName.MODULE_CREATE)
        val expected=MeshMessengerAppLock.currentEpoch()
        (context.reactContext as com.facebook.react.bridge.ReactApplicationContext).onHostResume(activity.get())
        assertSame("actual Expo context must expose the native prompt owner",activity.get(),context.currentActivity)
        val future=executor.submit<Any?> { suspendModuleCall(module,"authenticateAppLock",arrayOf(expected)) }
        waitFor { pending()!=null }; val request=pending()!!;val active=MeshMessengerAppLock.currentEpoch()
        try {
            nativeHost(context).reset();settle()
            assertNotEquals("native teardown must revoke before context reset",active,MeshMessengerAppLock.currentEpoch())
            val failure=assertThrows(ExecutionException::class.java) { future.get(5,TimeUnit.SECONDS) }
            assertTrue(failure.cause is IllegalStateException)
            assertThrows(IllegalStateException::class.java) { scope(module,context,MeshMessengerAppLock.currentEpoch()) }
        } finally {
            MeshMessengerAppLock.cancel(property(request,"id") as String)
            runCatching { future.get(5,TimeUnit.SECONDS) }
            moduleEvent(module,expo.modules.kotlin.events.EventName.MODULE_DESTROY)
        }
    }

    @Test fun staleNativeBeforeDestroyListenerCannotRevokeSuccessorOrBinding() = withActualModuleContext { oldContext ->
        configure("disabled")
        val old=MeshMessengerModule();oldContext.registry.register(old,null)
        moduleEvent(old,expo.modules.kotlin.events.EventName.MODULE_CREATE)
        val oldHost=nativeHost(oldContext)
        try {
            assertEquals("current module owns one native teardown listener",1,oldHost.listeners.size)
            val stale=oldHost.listeners.single()
            withActualModuleContext { freshContext ->
                val fresh=MeshMessengerModule();freshContext.registry.register(fresh,null)
                moduleEvent(fresh,expo.modules.kotlin.events.EventName.MODULE_CREATE)
                val expected=MeshMessengerAppLock.currentEpoch()
                try {
                    assertTrue("replacement detaches old native listener",oldHost.listeners.isEmpty())
                    stale();settle()
                    assertEquals(expected,MeshMessengerAppLock.currentEpoch());scope(fresh,freshContext,expected)
                    moduleEvent(old,expo.modules.kotlin.events.EventName.MODULE_DESTROY)
                    assertEquals(expected,MeshMessengerAppLock.currentEpoch());scope(fresh,freshContext,expected)
                } finally { moduleEvent(fresh,expo.modules.kotlin.events.EventName.MODULE_DESTROY) }
            }
        } finally { moduleEvent(old,expo.modules.kotlin.events.EventName.MODULE_DESTROY) }
    }

    @Test fun exactCurrentDisabledHeadlessRuntimeRegistersAndAdmitsWithoutActivity() = withActualModuleContext { context ->
        configure("disabled")
        field("owner").set(MeshMessengerAppLock,WeakReference<Activity>(null))
        field("resumed").setBoolean(MeshMessengerAppLock,false);field("ownedForeground").setBoolean(MeshMessengerAppLock,false)
        assertNull(context.currentActivity)
        val module=MeshMessengerModule();context.registry.register(module,null)
        try {
            moduleEvent(module,expo.modules.kotlin.events.EventName.MODULE_CREATE)
            scope(module,context,MeshMessengerAppLock.currentEpoch())
            assertEquals("disabled",MeshMessengerAppLock.state()["policy"])
        } finally { moduleEvent(module,expo.modules.kotlin.events.EventName.MODULE_DESTROY) }
    }

    // Actual src/codec.ts vectors output, accepted by parseProfileSummary.
    private fun canonicalProfile() = java.util.Base64.getDecoder().decode("AAAADU93bmVkIGZpeHR1cmUAAAAgAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAAAQAgICAgICAgICAgICAgICAgAAAAA=")
    private fun profilePacket(fields: List<ByteArray>): ByteArray {
        val bytes=java.io.ByteArrayOutputStream()
        java.io.DataOutputStream(bytes).use { out -> fields.forEach { out.writeInt(it.size);out.write(it) } }
        return bytes.toByteArray()
    }
    private fun bindBackupFiles(profile: ByteArray = canonicalProfile()): () -> Unit {
        val documents=File(RuntimeEnvironment.getApplication().filesDir,"backup-fixture-documents").apply { mkdirs() }
        return MeshMessengerProtectedFiles.bind({ expected -> MeshMessengerAppLock.requireEpoch(expected);profile.copyOf() },documents)
    }
    private fun backupFrame(purpose: String)=org.json.JSONObject().put("version",1).put("purpose",purpose)
    private fun beginBackup(purpose: String): String {
        val result=MeshMessengerProtectedFiles.dispatch("beginBackupChoice",backupFrame(purpose).toString(),ByteArray(0),MeshMessengerAppLock.currentEpoch()) as String
        return org.json.JSONObject(result).getString("requestId")
    }
    private fun launchBackupPicker(frame: org.json.JSONObject,operation: String,expected: String=MeshMessengerAppLock.currentEpoch()): Pair<Future<Any>,org.robolectric.shadows.ShadowActivity.IntentForResult> {
        val result=executor.submit<Any> { MeshMessengerProtectedFiles.dispatch(operation,frame.toString(),ByteArray(0),expected) }
        var launched: org.robolectric.shadows.ShadowActivity.IntentForResult?=null
        waitFor { launched=shadowOf(activity.get()).nextStartedActivityForResult;launched!=null || result.isDone }
        return result to checkNotNull(launched) { "actual provider never launched chooser" }
    }
    @Test fun backupPickerPauseRetainsMetadataButRecreatedEpochContextMisses() {
        configure("disabled");val release=bindBackupFiles();val old=MeshMessengerAppLock.currentEpoch()
        try {
            val context=backupFrame("export").put("filename","owned.bin").put("mimeType","application/octet-stream").put("size",1).put("sourceContext","backup-export/$old/1")
            val (result,launched)=launchBackupPicker(context,"chooseDestination",old)
            assertEquals(Intent.ACTION_CREATE_DOCUMENT,launched.intent.action)
            activity.pause().stop();settle();val fresh=MeshMessengerAppLock.currentEpoch();assertNotEquals(old,fresh)
            assertTrue(MeshMessengerProtectedFiles.activityResult(activity.get(),launched.requestCode,Activity.RESULT_OK,Intent().setData(android.net.Uri.parse("content://owned.backup/dest"))))
            assertThrows(ExecutionException::class.java) { result.get(5,TimeUnit.SECONDS) }
            activity.start().resume().visible();settle()
            val retained=org.json.JSONObject(MeshMessengerProtectedFiles.dispatch("pendingChoice",context.toString(),ByteArray(0),fresh) as String)
            val regenerated=org.json.JSONObject(context.toString()).put("sourceContext","backup-export/$fresh/2")
            assertFalse(org.json.JSONObject(MeshMessengerProtectedFiles.dispatch("pendingChoice",regenerated.toString(),ByteArray(0),fresh) as String).has("choiceId"))
            val claim=org.json.JSONObject(context.toString()).put("choiceId",retained.getString("choiceId"))
            val handle=org.json.JSONObject(MeshMessengerProtectedFiles.dispatch("beginExport",claim.toString(),ByteArray(0),fresh) as String).getString("handle")
            MeshMessengerProtectedFiles.dispatch("abortExport",org.json.JSONObject().put("version",1).put("handle",handle).toString(),ByteArray(0),fresh)
        } finally { release();MeshMessengerProtectedFiles.revoke() }
    }
    @Test fun backupDestinationRequestIsSingleMetadataOnlyAndExplicitCancelSuppressesLateSuccessor() {
        configure("disabled");val release=bindBackupFiles()
        try {
            val first=beginBackup("backup-export");val frame=backupFrame("backup-export").put("requestId",first)
            val (cancelled,old)=launchBackupPicker(frame,"chooseDestination")
            assertEquals(Intent.ACTION_CREATE_DOCUMENT,old.intent.action);assertEquals("application/octet-stream",old.intent.type)
            assertEquals("morse-backup.morsebackup",old.intent.getStringExtra(Intent.EXTRA_TITLE));assertFalse(old.intent.getBooleanExtra(Intent.EXTRA_ALLOW_MULTIPLE,false))
            MeshMessengerProtectedFiles.dispatch("discardBackupChoice",frame.toString(),ByteArray(0),MeshMessengerAppLock.currentEpoch())
            assertThrows(ExecutionException::class.java) { cancelled.get(5,TimeUnit.SECONDS) }
            val second=beginBackup("backup-export");val (current,next)=launchBackupPicker(backupFrame("backup-export").put("requestId",second),"chooseDestination")
            assertFalse(MeshMessengerProtectedFiles.activityResult(activity.get(),old.requestCode,Activity.RESULT_OK,Intent().setData(android.net.Uri.parse("content://owned.backup/old"))))
            assertTrue(MeshMessengerProtectedFiles.activityResult(activity.get(),next.requestCode,Activity.RESULT_OK,Intent().setData(android.net.Uri.parse("content://owned.backup/current"))))
            val selected=org.json.JSONObject(current.get(5,TimeUnit.SECONDS) as String)
            val choice=selected.getString("choiceId")
            val claim=backupFrame("backup-export").put("choiceId",choice).put("filename","morse-backup.morsebackup").put("mimeType","application/octet-stream").put("size",1).put("sourceContext","backup-export/${MeshMessengerAppLock.currentEpoch()}/1")
            assertThrows(Exception::class.java) { MeshMessengerProtectedFiles.dispatch("beginExport",org.json.JSONObject(claim.toString()).put("size",16796865).toString(),ByteArray(0),MeshMessengerAppLock.currentEpoch()) }
            val handle=org.json.JSONObject(MeshMessengerProtectedFiles.dispatch("beginExport",claim.toString(),ByteArray(0),MeshMessengerAppLock.currentEpoch()) as String).getString("handle")
            assertThrows(Exception::class.java) { MeshMessengerProtectedFiles.dispatch("beginExport",claim.toString(),ByteArray(0),MeshMessengerAppLock.currentEpoch()) }
            MeshMessengerProtectedFiles.dispatch("abortExport",org.json.JSONObject().put("version",1).put("handle",handle).toString(),ByteArray(0),MeshMessengerAppLock.currentEpoch())
        } finally { release();MeshMessengerProtectedFiles.revoke() }
    }
    class BackupDocumentProvider : android.content.ContentProvider() {
        companion object { var selected: File?=null;@Volatile var beforeQuery:(() -> Unit)?=null }
        override fun onCreate()=true
        override fun query(uri: android.net.Uri,projection:Array<out String>?,selection:String?,selectionArgs:Array<out String>?,sortOrder:String?):android.database.Cursor {
            beforeQuery?.invoke()
            return android.database.MatrixCursor(arrayOf(android.provider.OpenableColumns.DISPLAY_NAME,android.provider.OpenableColumns.SIZE)).apply { addRow(arrayOf<Any>("owned.backup",checkNotNull(selected).length())) }
        }
        override fun getType(uri:android.net.Uri)="application/octet-stream"
        override fun openFile(uri:android.net.Uri,mode:String)=android.os.ParcelFileDescriptor.open(checkNotNull(selected),android.os.ParcelFileDescriptor.MODE_READ_ONLY)
        override fun insert(uri:android.net.Uri,values:android.content.ContentValues?):android.net.Uri?=null
        override fun delete(uri:android.net.Uri,selection:String?,selectionArgs:Array<out String>?)=0
        override fun update(uri:android.net.Uri,values:android.content.ContentValues?,selection:String?,selectionArgs:Array<out String>?)=0
    }
    @Test fun backupSourceEnforcesInclusiveCiphertextQuotaSingleSelectionAndOnceOnlyClaim() {
        configure("disabled");val release=bindBackupFiles();val selected=File(RuntimeEnvironment.getApplication().cacheDir,"synthetic-backup-file")
        try {
            java.io.RandomAccessFile(selected,"rw").use { it.setLength(16796864) };BackupDocumentProvider.selected=selected
            val provider=Robolectric.buildContentProvider(BackupDocumentProvider::class.java).create(android.content.pm.ProviderInfo().apply { authority="owned.backup";exported=true }).get()
            org.robolectric.shadows.ShadowContentResolver.registerProviderInternal("owned.backup",provider)
            val (chosen,launched)=launchBackupPicker(backupFrame("backup-source").put("requestId",beginBackup("backup-source")),"chooseSource")
            assertEquals(Intent.ACTION_OPEN_DOCUMENT,launched.intent.action);assertFalse(launched.intent.getBooleanExtra(Intent.EXTRA_ALLOW_MULTIPLE,false))
            assertTrue(MeshMessengerProtectedFiles.activityResult(activity.get(),launched.requestCode,Activity.RESULT_OK,Intent().setData(android.net.Uri.parse("content://owned.backup/source"))))
            val choice=org.json.JSONObject(chosen.get(5,TimeUnit.SECONDS) as String);val files=choice.getJSONArray("files");assertEquals(1,files.length());val file=files.getJSONObject(0);assertEquals(16796864,file.getInt("size"))
            val claim=backupFrame("backup-source").put("sourceContext","backup-import/${MeshMessengerAppLock.currentEpoch()}/1").put("choiceId",choice.getString("choiceId")).put("selectionId",file.getString("selectionId")).put("size",16796864)
            val handle=org.json.JSONObject(MeshMessengerProtectedFiles.dispatch("claimSource",claim.toString(),ByteArray(0),MeshMessengerAppLock.currentEpoch()) as String).getString("handle")
            assertThrows(Exception::class.java) { MeshMessengerProtectedFiles.dispatch("claimSource",claim.toString(),ByteArray(0),MeshMessengerAppLock.currentEpoch()) }
            val range=org.json.JSONObject().put("version",1).put("handle",handle).put("offset",0).put("length",65536)
            assertEquals(65536,(MeshMessengerProtectedFiles.dispatch("readSource",range.toString(),ByteArray(0),MeshMessengerAppLock.currentEpoch()) as ByteArray).size)
            assertThrows(Exception::class.java) { MeshMessengerProtectedFiles.dispatch("readSource",org.json.JSONObject(range.toString()).put("length",65537).toString(),ByteArray(0),MeshMessengerAppLock.currentEpoch()) }
            MeshMessengerProtectedFiles.dispatch("closeSource",org.json.JSONObject().put("version",1).put("handle",handle).toString(),ByteArray(0),MeshMessengerAppLock.currentEpoch())
            java.io.RandomAccessFile(selected,"rw").use { it.setLength(16796865) }
            val (oversize,last)=launchBackupPicker(backupFrame("backup-source").put("requestId",beginBackup("backup-source")),"chooseSource")
            assertTrue(MeshMessengerProtectedFiles.activityResult(activity.get(),last.requestCode,Activity.RESULT_OK,Intent().setData(android.net.Uri.parse("content://owned.backup/source"))))
            assertThrows(ExecutionException::class.java) { oversize.get(5,TimeUnit.SECONDS) }
        } finally { release();MeshMessengerProtectedFiles.revoke();selected.delete();BackupDocumentProvider.selected=null }
    }

    @Test fun backupMetadataCrossingAccountGenerationNeverEntersTheChoiceCache() {
        configure("disabled");val release=bindBackupFiles();val selected=File(RuntimeEnvironment.getApplication().cacheDir,"synthetic-generation-backup")
        try {
            selected.writeBytes(byteArrayOf(1));BackupDocumentProvider.selected=selected
            val provider=Robolectric.buildContentProvider(BackupDocumentProvider::class.java).create(android.content.pm.ProviderInfo().apply { authority="owned.backup";exported=true }).get()
            org.robolectric.shadows.ShadowContentResolver.registerProviderInternal("owned.backup",provider)
            val request=beginBackup("backup-source");val (result,launched)=launchBackupPicker(backupFrame("backup-source").put("requestId",request),"chooseSource")
            BackupDocumentProvider.beforeQuery={ MeshMessengerAppLock.accountChanging() }
            assertTrue(MeshMessengerProtectedFiles.activityResult(activity.get(),launched.requestCode,Activity.RESULT_OK,Intent().setData(android.net.Uri.parse("content://owned.backup/source"))))
            assertThrows(ExecutionException::class.java) { result.get(5,TimeUnit.SECONDS) }
            val field=MeshMessengerProtectedFiles::class.java.getDeclaredField("choices").apply { isAccessible=true }
            val retained=field.get(MeshMessengerProtectedFiles) as Map<*,*>
            assertTrue("old generation metadata must be refused at final admission",retained.values.none { it!=null && property(it,"requestId")==request })
        } finally { BackupDocumentProvider.beforeQuery=null;release();MeshMessengerProtectedFiles.revoke();selected.delete();BackupDocumentProvider.selected=null }
    }

    @Suppress("UNCHECKED_CAST")
    private fun focusCoverMap() = field("covers").get(MeshMessengerAppLock) as MutableMap<Activity,Dialog>
    private fun focusReadyCover(): Dialog {
        configure("disabled")
        field("activatedEpoch").set(MeshMessengerAppLock,null)
        MeshMessengerAppLock::class.java.getDeclaredMethod("showCover",Activity::class.java).apply { isAccessible=true }.invoke(MeshMessengerAppLock,activity.get())
        settle()
        val cover=checkNotNull(focusCoverMap()[activity.get()])
        assertTrue(cover.isShowing)
        field("ownedForeground").setBoolean(MeshMessengerAppLock,false)
        field("activatedEpoch").set(MeshMessengerAppLock,MeshMessengerAppLock.currentEpoch())
        return cover
    }
    @Test fun nativeCoverFocusDispatchDefersDismissUntilTheNextMainTurn() {
        val cover=focusReadyCover()
        cover.onWindowFocusChanged(true)
        assertTrue("The focus callback must return with its current window attached",cover.isShowing)
        settle()
        assertFalse("Current exact authorized cover dismisses on the next main turn",cover.isShowing)
        assertNull(focusCoverMap()[activity.get()])
    }
    @Test fun nativeCoverQueuedDismissalCannotHideANewLockedEpoch() {
        val cover=focusReadyCover();val original=MeshMessengerAppLock.currentEpoch()
        cover.onWindowFocusChanged(true)
        MeshMessengerAppLock.lock()
        val locked=checkNotNull(focusCoverMap()[activity.get()])
        settle()
        assertNotEquals(original,MeshMessengerAppLock.currentEpoch())
        assertEquals("locked",MeshMessengerAppLock.state()["phase"])
        assertSame(locked,focusCoverMap()[activity.get()]);assertTrue(locked.isShowing)
        assertTrue(locked.window!!.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0)
    }
    @Test fun nativeCoverQueuedDismissalCannotRetargetAReplacementCover() {
        val original=focusReadyCover()
        coverReplacement@ try {
            original.onWindowFocusChanged(true)
            val constructor=Class.forName("expo.modules.meshmessenger.MeshMessengerAppLock\$NativeCover").getDeclaredConstructor(Activity::class.java).apply { isAccessible=true }
            val replacement=constructor.newInstance(activity.get()) as Dialog
            replacement.setContentView(TextView(activity.get()).apply { text="synthetic replacement cover" })
            focusCoverMap()[activity.get()]=replacement;replacement.show()
            original.javaClass.getDeclaredField("handingOff").apply { isAccessible=true }.setBoolean(original,true)
            original.dismiss()
            shadowOf(Looper.getMainLooper()).runOneTask()
            assertSame(replacement,focusCoverMap()[activity.get()])
            assertTrue("The old queued callback must not hide a distinct current cover",replacement.isShowing)
        } finally {
            if(original.isShowing) {
                original.javaClass.getDeclaredField("handingOff").apply { isAccessible=true }.setBoolean(original,true)
                original.dismiss()
            }
        }
    }

    @Test fun actualCodecFourVectorProfileBindsPreferencesAndBackupIntentWithoutPicker() {
        configure("disabled");val profile=canonicalProfile();val release=bindBackupFiles(profile)
        val target=File(RuntimeEnvironment.getApplication().filesDir,"backup-fixture-documents/read-state-${"01".repeat(32)}.json")
        try {
            assertArrayEquals(profilePacket(listOf("Owned fixture".toByteArray(),ByteArray(32){1},ByteArray(16){2},ByteArray(0))),profile)
            target.writeText("owned-read-status")
            assertEquals("owned-read-status",MeshMessengerProtectedFiles.readLegacy(profile,"read-state",MeshMessengerAppLock.currentEpoch()))
            assertTrue(beginBackup("backup-export").isNotEmpty())
            assertNull(shadowOf(activity.get()).nextStartedActivityForResult)
        } finally { target.delete();release();MeshMessengerProtectedFiles.revoke() }
    }
    @Test fun exact36134ByteCodecFrameBindsNativeIdentity() {
        configure("disabled")
        val profile=profilePacket(listOf(ByteArray(64){65},ByteArray(32){1},ByteArray(16){2},ByteArray(36006){7}))
        assertEquals(36134,profile.size)
        assertEquals("68551975240a1d1a1904d1b71c628717f70cd68d4d26f42c3911390d8ea771fa",java.security.MessageDigest.getInstance("SHA-256").digest(profile).joinToString(""){"%02x".format(it.toInt() and 255)})
        val release=bindBackupFiles(profile)
        try {
            assertNull(MeshMessengerProtectedFiles.readLegacy(profile,"read-state",MeshMessengerAppLock.currentEpoch()))
            assertTrue(beginBackup("backup-source").isNotEmpty())
        } finally { release();MeshMessengerProtectedFiles.revoke() }
    }
    @Test fun countPrefixedTruncatedTrailingOversizedAndWrongIdentityFramesRefuseBeforeIO() {
        configure("disabled");val profile=canonicalProfile()
        val maximum=profilePacket(listOf(ByteArray(64){65},ByteArray(32){1},ByteArray(16){2},ByteArray(36006){7}))
        val malformed=listOf(byteArrayOf(0,0,0,4)+profile,profile.copyOf(profile.size-1),profile+byteArrayOf(0),maximum+byteArrayOf(0),
            profilePacket(listOf("Owned fixture".toByteArray(),ByteArray(31){1},ByteArray(16){2},ByteArray(0))),
            profilePacket(listOf("Owned fixture".toByteArray(),ByteArray(32){1},ByteArray(15){2},ByteArray(0))),
            profilePacket(listOf(ByteArray(65){65},ByteArray(32){1},ByteArray(16){2},ByteArray(0))),
            profilePacket(listOf("Owned fixture".toByteArray(),ByteArray(32){1},ByteArray(16){2},ByteArray(36007){7})))
        for(value in malformed) {
            val release=bindBackupFiles(value)
            try {
                assertThrows(Exception::class.java){MeshMessengerProtectedFiles.readLegacy(value,"read-state",MeshMessengerAppLock.currentEpoch())}
                assertThrows(Exception::class.java){beginBackup("backup-export")}
                assertNull(shadowOf(activity.get()).nextStartedActivityForResult)
            } finally { release();MeshMessengerProtectedFiles.revoke() }
        }
    }

}
