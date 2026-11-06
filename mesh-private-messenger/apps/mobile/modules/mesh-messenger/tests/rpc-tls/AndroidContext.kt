package android.content

import android.content.pm.PackageManager
import android.content.res.AssetManager

class Context(val assets: AssetManager) {
    val packageName = "app.morse.rpc-tls-proof"
    val packageManager = PackageManager()
}
