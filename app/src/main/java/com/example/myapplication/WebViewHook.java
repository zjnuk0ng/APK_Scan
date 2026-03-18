package com.example.myapplication;

import android.util.Log;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class WebViewHook {

    private static final String TAG = "SEC_SCAN";

    // 定义不同级别的 Log 标识
    private static final String INFO = "[INFO] ";       // 普通配置信息
    private static final String WARN = "[WARNING] ";    // 存在潜在风险的配置
    private static final String CRITICAL = "[CRITICAL] "; // 极高危漏洞风险
    private static final String VULN_XSS = "[VULN_XSS] ";
    private static final String VULN_FILE = "[VULN_FILE] ";
    private static final String VULN_URL = "[VULN_URL] ";

    public static void init(XC_LoadPackage.LoadPackageParam lpparam) {
        hookWebSettings(lpparam);
        hookAddJSInterface(lpparam);
        hookLoadUrl(lpparam);
        hookWebViewClient(lpparam);
    }

    // 1. 探测 WebSettings 安全配置
    private static void hookWebSettings(XC_LoadPackage.LoadPackageParam lpparam) {
        Class<?> webSettingsClass = XposedHelpers.findClass("android.webkit.WebSettings", lpparam.classLoader);

        // 检测 JavaScript 开关
        XposedHelpers.findAndHookMethod(webSettingsClass, "setJavaScriptEnabled", boolean.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                boolean enabled = (boolean) param.args[0];
                if (enabled) {
                    Log.w(TAG, VULN_XSS + "JavaScript is ENABLED. Potential XSS entry point.");
                }
            }
        });

        // 检测文件访问权限 (file://)
        XposedHelpers.findAndHookMethod(webSettingsClass, "setAllowFileAccess", boolean.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                boolean allowed = (boolean) param.args[0];
                if (allowed) {
                    Log.w(TAG, VULN_FILE + "setAllowFileAccess(true): App can read local files via file://");
                }
            }
        });

        // 跨域文件访问：最重要的两个文件读取漏洞开关
        XposedHelpers.findAndHookMethod(webSettingsClass, "setAllowFileAccessFromFileURLs", boolean.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                if ((boolean) param.args[0]) {
                    Log.e(TAG, CRITICAL + "setAllowFileAccessFromFileURLs(true): HIGH RISK! File-based XSS can steal local files.");
                }
            }
        });

        XposedHelpers.findAndHookMethod(webSettingsClass, "setAllowUniversalAccessFromFileURLs", boolean.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                if ((boolean) param.args[0]) {
                    Log.e(TAG, CRITICAL + "setAllowUniversalAccessFromFileURLs(true): EXTREME RISK! Any file can bypass SOP.");
                }
            }
        });
    }

    // 2. JSBridge 导出接口探测
    private static void hookAddJSInterface(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedHelpers.findAndHookMethod("android.webkit.WebView", lpparam.classLoader, "addJavascriptInterface",
                Object.class, String.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        String name = (String) param.args[1];
                        Object obj = param.args[0];
                        Log.i(TAG, VULN_XSS + "JSBridge Exported -> Name: " + name + " | Class: " + obj.getClass().getName());
                        // 打印调用栈，确认是在哪里导出的
                        // Log.d(TAG, Log.getStackTraceString(new Throwable()));
                    }
                });
    }

    // 3. 拦截 URL 加载，探测敏感协议
    private static void hookLoadUrl(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedHelpers.findAndHookMethod("android.webkit.WebView", lpparam.classLoader, "loadUrl", String.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                String url = (String) param.args[0];
                if (url == null) return;

                Log.i(TAG, VULN_URL + "Loading URL: " + url);

                if (url.startsWith("file:///android_asset/") || url.startsWith("file:///sdcard/")) {
                    Log.w(TAG, VULN_FILE + "Loading local file: " + url);
                } else if (url.startsWith("javascript:")) {
                    Log.w(TAG, VULN_XSS + "Executing Inline JS: " + url);
                } else if (url.startsWith("http://")) {
                    Log.w(TAG, WARN + "Insecure Cleartext HTTP: " + url);
                }
            }
        });
    }

    // 4. 探测外部页面打开逻辑 (shouldOverrideUrlLoading)
    private static void hookWebViewClient(XC_LoadPackage.LoadPackageParam lpparam) {
        // 由于 shouldOverrideUrlLoading 是在子类中实现的，我们 Hook WebView 的 setWebViewClient 方法
        // 然后动态 Hook 传入的对象
        XposedHelpers.findAndHookMethod("android.webkit.WebView", lpparam.classLoader, "setWebViewClient",
                "android.webkit.WebViewClient", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        Object client = param.args[0];
                        if (client == null) return;

                        Log.i(TAG, INFO + "WebViewClient set: " + client.getClass().getName());

                        // Hook 该 Client 的 URL 过滤逻辑
                        try {
                            XposedHelpers.findAndHookMethod(client.getClass(), "shouldOverrideUrlLoading",
                                    WebView.class, String.class, new XC_MethodHook() {
                                        @Override
                                        protected void afterHookedMethod(MethodHookParam param) {
                                            Log.d(TAG, VULN_URL + "shouldOverrideUrlLoading(String) returned: " + param.getResult() + " for URL: " + param.args[1]);
                                        }
                                    });
                        } catch (Throwable ignored) {}

                        try {
                            XposedHelpers.findAndHookMethod(client.getClass(), "shouldOverrideUrlLoading",
                                    WebView.class, WebResourceRequest.class, new XC_MethodHook() {
                                        @Override
                                        protected void afterHookedMethod(MethodHookParam param) {
                                            WebResourceRequest request = (WebResourceRequest) param.args[1];
                                            Log.d(TAG, VULN_URL + "shouldOverrideUrlLoading(Request) returned: " + param.getResult() + " for URL: " + request.getUrl());
                                        }
                                    });
                        } catch (Throwable ignored) {}
                    }
                });
    }
}