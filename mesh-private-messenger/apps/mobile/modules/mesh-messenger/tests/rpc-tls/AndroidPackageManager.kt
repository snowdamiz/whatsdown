package android.content.pm

import android.os.Bundle

class ApplicationInfo { val metaData: Bundle? = null }
class PackageManager {
    companion object { const val GET_META_DATA = 128 }
    fun getApplicationInfo(name: String, flags: Int): ApplicationInfo {
        check(name.isNotEmpty() && flags == GET_META_DATA)
        return ApplicationInfo()
    }
}
