package com.example.myapplication;

import android.content.Context;
import android.content.pm.*;
import android.os.Build;
import android.provider.Settings;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.security.MessageDigest;
import java.util.List;

public class SecurityUtils {

    public static String collectBaseline(Context context) {
        if (context == null) return "{}";

        try {
            PackageManager pm = context.getPackageManager();
            String pkgName = context.getPackageName();
            PackageInfo pi = pm.getPackageInfo(pkgName,
                    PackageManager.GET_PERMISSIONS |
                            PackageManager.GET_ACTIVITIES |
                            PackageManager.GET_SERVICES |
                            PackageManager.GET_PROVIDERS |
                            PackageManager.GET_SIGNING_CERTIFICATES);

            ApplicationInfo ai = context.getApplicationInfo();

            JSONObject json = new JSONObject();

            // ======================
            // 基本信息
            // ======================
            json.put("packageName", pkgName);
            json.put("versionName", pi.versionName);
            json.put("versionCode", (Build.VERSION.SDK_INT >= 28)
                    ? pi.getLongVersionCode() : pi.versionCode);
            json.put("targetSdkVersion", ai.targetSdkVersion);
            json.put("minSdkVersion", ai.minSdkVersion);

            // 安全配置
            boolean debuggable = (ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
            boolean allowBackup = (ai.flags & ApplicationInfo.FLAG_ALLOW_BACKUP) != 0;

            json.put("debuggable", debuggable);
            json.put("allowBackup", allowBackup);

            // 权限信息
            JSONArray perms = new JSONArray();
            if (pi.requestedPermissions != null) {
                for (String p : pi.requestedPermissions) {
                    perms.put(p);
                }
            }
            json.put("permissions", perms);

            // 组件暴露
            json.put("exportedActivities", getExported(pi.activities));
            json.put("exportedServices", getExported(pi.services));
            json.put("exportedProviders", getExportedProviders(pi.providers));

            // 签名信息（指纹）
            if (Build.VERSION.SDK_INT >= 28 && pi.signingInfo != null) {
                byte[] cert = pi.signingInfo.getApkContentsSigners()[0].toByteArray();
                json.put("signatureSHA256", sha256(cert));
            }

            // 网络安全
            json.put("usesCleartextTraffic", usesCleartext(ai));
            json.put("proxy", getProxy());

            // 设备环境（安全检测）
            json.put("deviceModel", Build.MODEL);
            json.put("brand", Build.BRAND);
            json.put("manufacturer", Build.MANUFACTURER);
            json.put("abi", Build.SUPPORTED_ABIS[0]);

            json.put("isEmulator", isEmulator());
            json.put("isRooted", isRooted());

            // WebView 相关
            json.put("webviewVersion", getWebViewVersion());

            // App路径信息
            json.put("apkPath", ai.sourceDir);
            json.put("dataDir", ai.dataDir);

            return json.toString(2);

        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage() + "\"}";
        }
    }

    // 工具方法
    private static JSONArray getExported(ComponentInfo[] components) {
        JSONArray arr = new JSONArray();
        if (components == null) return arr;

        for (ComponentInfo c : components) {
            if (c.exported) {
                arr.put(c.name);
            }
        }
        return arr;
    }

    private static JSONArray getExportedProviders(ProviderInfo[] providers) {
        JSONArray arr = new JSONArray();
        if (providers == null) return arr;

        for (ProviderInfo p : providers) {
            if (p.exported) {
                arr.put(p.authority);
            }
        }
        return arr;
    }

    private static boolean usesCleartext(ApplicationInfo ai) {
        try {
            if (Build.VERSION.SDK_INT >= 23) {
                return (boolean) ApplicationInfo.class
                        .getMethod("usesCleartextTraffic")
                        .invoke(ai);
            }
        } catch (Exception ignored) {}

        return true; // 默认认为存在风险
    }

    private static String getProxy() {
        try {
            return System.getProperty("http.proxyHost") + ":" +
                    System.getProperty("http.proxyPort");
        } catch (Exception e) {
            return "none";
        }
    }

    private static boolean isEmulator() {
        return Build.FINGERPRINT.contains("generic")
                || Build.MODEL.contains("Emulator")
                || Build.HARDWARE.contains("goldfish");
    }

    private static boolean isRooted() {
        String[] paths = {
                "/system/bin/su",
                "/system/xbin/su",
                "/sbin/su",
                "/system/app/Superuser.apk"
        };

        for (String path : paths) {
            if (new File(path).exists()) return true;
        }
        return false;
    }

    private static String sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(data);

            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                hex.append(String.format("%02X", b));
            }
            return hex.toString();

        } catch (Exception e) {
            return "error";
        }
    }

    private static String getWebViewVersion() {
        try {
            if (Build.VERSION.SDK_INT >= 26) {
                PackageInfo pi = android.webkit.WebView.getCurrentWebViewPackage();
                return pi.packageName + " " + pi.versionName;
            }
        } catch (Throwable ignored) {}

        return "unknown";
    }
}