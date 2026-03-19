package com.example.myapplication;

import android.app.Application;
import android.content.Context;
import android.util.Log;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import dalvik.system.DexClassLoader;
import dalvik.system.PathClassLoader;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class SDKHook {

    private static final String TAG = "SEC_SCAN";

    private static final String SDK_CLASS = "SDK_CLASS";
    private static final String SDK_DEX = "SDK_DYNAMIC_LOAD";
    private static final String SDK_NETWORK = "SDK_NETWORK";

    private static final Map<String, String> SDK_RULES = new HashMap<>();
    private static final Set<String> SEEN_CLASSES = new HashSet<>();
    private static final ThreadLocal<Boolean> GUARD = new ThreadLocal<>();

    static {
        SDK_RULES.put("com.facebook.", "Facebook SDK");
        SDK_RULES.put("com.google.firebase.", "Firebase");
        SDK_RULES.put("com.appsflyer.", "AppsFlyer");
        SDK_RULES.put("com.adjust.", "Adjust");
        SDK_RULES.put("com.tencent.bugly.", "Bugly");
        SDK_RULES.put("okhttp3.", "OkHttp");
    }

    public static void init(final XC_LoadPackage.LoadPackageParam lpparam) {

        // 只 hook 目标 App
        if (!lpparam.packageName.equals("com.app99.driver")) return;

        // 延迟到 Application.attach
        XposedHelpers.findAndHookMethod(
                Application.class,
                "attach",
                Context.class,
                new XC_MethodHook() {

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {

                        ClassLoader cl = ((Context) param.args[0]).getClassLoader();

                        hookClassLoader(lpparam, cl);
                        hookDexLoader(lpparam);
                        hookNetwork(lpparam, cl);

                        Log.i(TAG, "SDKHook initialized safely");
                    }
                }
        );
    }

    // hook App ClassLoader
    private static void hookClassLoader(final XC_LoadPackage.LoadPackageParam lpparam, ClassLoader cl) {

        XposedHelpers.findAndHookMethod(
                cl.getClass(),
                "loadClass",
                String.class,
                new XC_MethodHook() {

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {

                        if (Boolean.TRUE.equals(GUARD.get())) return;
                        GUARD.set(true);

                        try {
                            String className = (String) param.args[0];
                            if (className == null) return;

                            // 强过滤（关键）
                            if (className.startsWith("java.") ||
                                    className.startsWith("android.") ||
                                    className.startsWith("kotlin.") ||
                                    className.startsWith("sun.") ||
                                    className.startsWith("dalvik.") ||
                                    className.startsWith("androidx.")) {
                                return;
                            }

                            if (!SEEN_CLASSES.add(className)) return;

                            String sdk = matchSDK(className);
                            if (sdk != null) {
                                report(lpparam.packageName, SDK_CLASS,
                                        sdk + " -> " + className);
                            }

                        } catch (Throwable ignored) {
                        } finally {
                            GUARD.set(false);
                        }
                    }
                }
        );
    }

    // 动态 Dex 加载
    private static void hookDexLoader(final XC_LoadPackage.LoadPackageParam lpparam) {

        XposedHelpers.findAndHookConstructor(
                DexClassLoader.class,
                String.class, String.class, String.class, ClassLoader.class,
                new XC_MethodHook() {

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        try {
                            String dexPath = (String) param.args[0];
                            report(lpparam.packageName, SDK_DEX,
                                    "Dynamic Dex Loaded: " + dexPath);
                        } catch (Throwable ignored) {}
                    }
                }
        );
    }


    // 网络识别
    private static void hookNetwork(final XC_LoadPackage.LoadPackageParam lpparam, ClassLoader cl) {

        try {
            Class<?> requestClass = cl.loadClass("okhttp3.Request");

            XposedHelpers.findAndHookMethod(
                    requestClass,
                    "url",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            try {
                                Object urlObj = param.getResult();
                                if (urlObj == null) return;

                                String url = urlObj.toString();
                                String sdk = matchSDKByHost(url);

                                if (sdk != null) {
                                    report(lpparam.packageName, SDK_NETWORK,
                                            sdk + " -> " + url);
                                }
                            } catch (Throwable ignored) {}
                        }
                    }
            );

        } catch (Throwable ignored) {
            // 不存在OkHttp时不会崩
        }
    }

    // 匹配逻辑
    private static String matchSDK(String className) {
        for (String prefix : SDK_RULES.keySet()) {
            if (className.startsWith(prefix)) {
                return SDK_RULES.get(prefix);
            }
        }
        return null;
    }

    private static String matchSDKByHost(String url) {
        if (url.contains("facebook.com")) return "Facebook SDK";
        if (url.contains("firebase")) return "Firebase";
        if (url.contains("appsflyer.com")) return "AppsFlyer";
        if (url.contains("adjust.com")) return "Adjust";
        return null;
    }

    private static void report(String pkg, String type, String msg) {
        Log.i(TAG, "[" + type + "] " + msg);
        Report.reportEvent(pkg, type, msg);
    }
}