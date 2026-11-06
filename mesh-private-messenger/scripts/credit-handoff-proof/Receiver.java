package app.morse.handoff.receiver;
import android.app.Activity;
import android.os.Bundle;
import android.content.Intent;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import org.json.JSONObject;

/** Owned receiver only. Records OS delivery and never pays. */
public final class Receiver extends Activity {
  @Override public void onCreate(Bundle state) { super.onCreate(state); record(getIntent()); finish(); }
  @Override public void onNewIntent(Intent intent) { super.onNewIntent(intent); record(intent); finish(); }
  private void record(Intent intent) {
    try {
      String uri = intent.getDataString();
      if (uri == null) throw new IllegalArgumentException("missing URI");
      File file = new File(getFilesDir(), "received.json");
      int count = file.exists() ? new JSONObject(new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8)).getInt("count") : 0;
      StringBuilder digest = new StringBuilder();
      for (byte value : MessageDigest.getInstance("SHA-256").digest(uri.getBytes(StandardCharsets.UTF_8))) digest.append(String.format("%02x", value & 255));
      JSONObject output = new JSONObject().put("count", count + 1).put("sha256", digest.toString()).put("scheme", intent.getData().getScheme()).put("length", uri.getBytes(StandardCharsets.UTF_8).length);
      File temp = new File(getFilesDir(), "received.tmp");
      Files.write(temp.toPath(), output.toString().getBytes(StandardCharsets.UTF_8));
      if (!temp.renameTo(file)) throw new IllegalStateException("commit failed");
    } catch (Exception error) { throw new IllegalStateException("receiver failed", error); }
  }
}
