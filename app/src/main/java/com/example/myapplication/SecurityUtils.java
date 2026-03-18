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

    private static final String TAG = "SEC_UTILS";
    // 10.0.2.2 是模拟器访问宿主机的特殊 IP
    private static final String BASELINE_URL = "http://10.0.2.2:8080/report/baseline";
    private static final String EVENT_URL = "http://10.0.2.2:8080/report/event";

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

    public static void reportToBackend(String data) {
        sendPost(BASELINE_URL, data);
    }

    public static void reportEvent(String packageName, String type, String message) {
        try {
            JSONObject json = new JSONObject();
            json.put("packageName", packageName);
            json.put("type", type);
            json.put("message", message);
            json.put("timestamp", System.currentTimeMillis());
            sendPost(EVENT_URL, json.toString());
        } catch (Exception e) {
            Log.e(TAG, "JSON Error", e);
        }
    }

    private static void sendPost(final String targetUrl, final String data) {
        new Thread(() -> {
            HttpURLConnection conn = null;
            try {
                URL url = new URL(targetUrl);
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                conn.setConnectTimeout(5000);
                conn.setDoOutput(true);

                // 使用 BufferedOutputStream 提高稳定性，防止 Connection Reset
                try (OutputStream os = new BufferedOutputStream(conn.getOutputStream())) {
                    byte[] input = data.getBytes(StandardCharsets.UTF_8);
                    os.write(input, 0, input.length);
                    os.flush();
                }

                int code = conn.getResponseCode();
                Log.i(TAG, "Report Success [" + code + "] -> " + targetUrl);
            } catch (Exception e) {
                Log.e(TAG, "Network Error: " + e.getMessage());
            } finally {
                if (conn != null) conn.disconnect();
            }
        }).start();
    }
}
