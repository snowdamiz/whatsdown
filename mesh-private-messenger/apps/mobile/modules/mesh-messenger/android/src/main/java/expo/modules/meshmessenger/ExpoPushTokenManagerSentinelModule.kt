package expo.modules.meshmessenger

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

class ExpoPushTokenManagerSentinelModule : Module() {
    override fun definition() = ModuleDefinition {
        Name("ExpoPushTokenManager")
        Events("onDevicePushToken")
    }
}
