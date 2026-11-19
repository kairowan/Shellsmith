package dev.mocika.shield.loader;

import android.content.Context;

/** 本地密钥变体不链接网络模块；覆盖安装时丢弃旧待报状态。 */
final class ByosRiskEvents {
    static void initialize(Context context) {
        java.io.File[] files = new java.io.File(context.getApplicationInfo().dataDir, "shared_prefs")
                .listFiles((directory, name) -> name.matches("shellsmith_risk_v1(?:_[0-9a-f]{16})?(?:_auth)?\\.xml"));
        if (files != null) for (java.io.File file : files) context.getSharedPreferences(
                file.getName().substring(0, file.getName().length() - 4), Context.MODE_PRIVATE).edit().clear().apply();
    }
}
