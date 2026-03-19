package com.example.myapplication;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedOutputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class SecurityUtils {

    public static String collectBaseline(Context context) {
        if (context == null) return "{}";
        try {
            PackageManager pm = context.getPackageManager();
            String pkgName = context.getPackageName();
            PackageInfo pi = pm.getPackageInfo(pkgName, 0);
            ApplicationInfo ai = context.getApplicationInfo();

            JSONObject json = new JSONObject();
            json.put("packageName", pkgName);
            json.put("versionName", pi.versionName);
            json.put("versionCode", (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) ? pi.getLongVersionCode() : pi.versionCode);
            json.put("targetSdkVersion", ai.targetSdkVersion);

            // 风险项判断逻辑
            boolean debuggable = (ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
            boolean allowBackup = (ai.flags & ApplicationInfo.FLAG_ALLOW_BACKUP) != 0;
            boolean usesCleartext = true;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                //usesCleartext = ai.usesCleartextTraffic();
            }

            json.put("debuggable", debuggable);
            json.put("allowBackup", allowBackup);
            json.put("usesCleartextTraffic", usesCleartext);
            json.put("deviceModel", Build.MODEL);

            return json.toString(4);
        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage() + "\"}";
        }
    }

}
