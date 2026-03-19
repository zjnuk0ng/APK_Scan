package com.example.myapplication;

import android.util.Log;

import java.util.HashMap;
import java.util.Map;

import dalvik.system.DexClassLoader;
import dalvik.system.PathClassLoader;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class SDKHook {

    private static final String TAG = "SEC_SCAN";

    // 类型定义
    private static final String SDK_CLASS = "SDK_CLASS";
    private static final String SDK_DEX = "SDK_DYNAMIC_LOAD";
    private static final String SDK_SO = "SDK_NATIVE_LOAD";
    private static final String SDK_NETWORK = "SDK_NETWORK";

    // SDK 指纹
    private static final Map<String, String> SDK_RULES = new HashMap<>();

    static {
        SDK_RULES.put("com.facebook.", "Facebook SDK");
        SDK_RULES.put("com.google.firebase.", "Firebase");
        SDK_RULES.put("com.appsflyer.", "AppsFlyer");
        SDK_RULES.put("com.adjust.", "Adjust");
        SDK_RULES.put("com.tencent.bugly.", "Bugly");
        SDK_RULES.put("okhttp3.", "OkHttp");
    }

    public static void init(final XC_LoadPackage.LoadPackageParam lpparam) {
        hookClassLoader(lpparam);
        hookDexLoader(lpparam);
        hookSoLoad(lpparam);
        hookNetwork(lpparam);
    }

    // 监测 ClassLoader → Java SDK 识别
    private static void hookClassLoader(final XC_LoadPackage.LoadPackageParam lpparam) {
        XposedHelpers.findAndHookMethod(
                ClassLoader.class,
                "loadClass",
                String.class,
                new XC_MethodHook() {

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        String className = (String) param.args[0];
                        if (className == null) return;

                        String sdk = matchSDK(className);
                        if (sdk != null) {
                            report(lpparam.packageName, SDK_CLASS,
                                    sdk + " -> " + className);
                        }
                    }
                }
        );
    }

    // 监测动态 Dex 加载（插件/热更新）
    private static void hookDexLoader(final XC_LoadPackage.LoadPackageParam lpparam) {
        XposedHelpers.findAndHookConstructor(
                DexClassLoader.class,
                String.class, String.class, String.class, ClassLoader.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        String dexPath = (String) param.args[0];
                        report(lpparam.packageName, SDK_DEX,
                                "Dynamic Dex Loaded: " + dexPath);
                    }
                }
        );
    }

    // 监测 Native SO 加载
    private static void hookSoLoad(final XC_LoadPackage.LoadPackageParam lpparam) {

        // System.loadLibrary
        XposedHelpers.findAndHookMethod(
                System.class,
                "loadLibrary",
                String.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        String lib = (String) param.args[0];
                        report(lpparam.packageName, SDK_SO,
                                "loadLibrary: " + lib);
                    }
                }
        );

        // System.load
        XposedHelpers.findAndHookMethod(
                System.class,
                "load",
                String.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        String path = (String) param.args[0];
                        report(lpparam.packageName, SDK_SO,
                                "load SO Path: " + path);
                    }
                }
        );
    }

    // 域名识别SDK
    private static void hookNetwork(final XC_LoadPackage.LoadPackageParam lpparam) {

        try {
            Class<?> requestClass = XposedHelpers.findClass(
                    "okhttp3.Request",
                    lpparam.classLoader
            );

            XposedHelpers.findAndHookMethod(
                    requestClass,
                    "url",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            Object urlObj = param.getResult();
                            if (urlObj == null) return;

                            String url = urlObj.toString();
                            String sdk = matchSDKByHost(url);

                            if (sdk != null) {
                                report(lpparam.packageName, SDK_NETWORK,
                                        sdk + " -> " + url);
                            }
                        }
                    }
            );

        } catch (Throwable ignored) {
        }
    }

    // SDK 快速匹配逻辑
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

    // 数据上报
    private static void report(String pkg, String type, String msg) {
        Log.i(TAG, "[" + type + "] " + msg);
        Report.reportEvent(pkg, type, msg);
    }
}