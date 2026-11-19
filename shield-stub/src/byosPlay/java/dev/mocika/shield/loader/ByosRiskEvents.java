package dev.mocika.shield.loader;

import android.content.Context;
import java.security.KeyPair;

/** Play-only 没有登记的安装密钥，禁止匿名或使用构建凭据降级。 */
final class ByosRiskEvents {
    static void initialize(Context context) {
        java.io.File[] files = new java.io.File(context.getApplicationInfo().dataDir, "shared_prefs")
                .listFiles((directory, name) -> name.matches("shellsmith_risk_v1(?:_[0-9a-f]{16})?(?:_auth)?\\.xml"));
        if (files != null) for (java.io.File file : files) context.getSharedPreferences(
                file.getName().substring(0, file.getName().length() - 4), Context.MODE_PRIVATE).edit().clear().apply();
    }
    static void resume(Context c, String e, String t, String b, String g, KeyPair k) { }
    static void authorized(Context c, String e, String t, String b, String g, KeyPair k, org.json.JSONObject response) { }
}
