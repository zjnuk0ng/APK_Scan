package com.example.myapplication;

import android.util.Log;
import android.webkit.WebSettings;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class WebViewHook {

    private static final String TAG = "SEC_SCAN";

    // 漏洞类型
    private static final String VULN_XSS = "VULN_XSS";
    private static final String VULN_FILE = "VULN_FILE";
    private static final String VULN_URL = "VULN_URL";
    private static final String VULN_CONFIG = "VULN_CONFIG";

    public static void init(XC_LoadPackage.LoadPackageParam lpparam) {
        // 不再 Hook WebSettings 抽象类，改为在行为触发时检查
        hookAddJSInterface(lpparam);
        hookLoadUrl(lpparam);
        hookWebViewClient(lpparam);
    }

    // 辅助方法：检查 WebView 的各项配置
    private static void checkWebViewSettings(WebView webView, String packageName) {
        try {
            WebSettings settings = webView.getSettings();
            if (settings == null) return;

            if (settings.getJavaScriptEnabled()) {
                report(packageName, VULN_CONFIG, "Running with JavaScript ENABLED");
            }
            if (settings.getAllowFileAccess()) {
                report(packageName, VULN_CONFIG, "Running with AllowFileAccess ENABLED");
            }

            // 检查跨域文件访问 (API 16+)
            boolean allowFileAny = (boolean) XposedHelpers.callMethod(settings, "getAllowFileAccessFromFileURLs");
            boolean allowUniversal = (boolean) XposedHelpers.callMethod(settings, "getAllowUniversalAccessFromFileURLs");

            if (allowFileAny) {
                report(packageName, VULN_FILE, "CRITICAL: AllowFileAccessFromFileURLs is TRUE");
            }
            if (allowUniversal) {
                report(packageName, VULN_FILE, "CRITICAL: AllowUniversalAccessFromFileURLs is TRUE");
            }
        } catch (Throwable t) {
            // 防止某些厂商定制 WebView 导致崩溃
        }
    }

    // 1. JSBridge 导出接口探测
    private static void hookAddJSInterface(final XC_LoadPackage.LoadPackageParam lpparam) {
        XposedHelpers.findAndHookMethod(WebView.class, "addJavascriptInterface",
                Object.class, String.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        String name = (String) param.args[1];
                        Object obj = param.args[0];
                        String msg = "JSBridge Exported -> Name: " + name + " | Class: " + obj.getClass().getName();
                        report(lpparam.packageName, VULN_XSS, msg);

                        // 导出接口时顺便检查一下配置
                        checkWebViewSettings((WebView) param.thisObject, lpparam.packageName);
                    }
                });
    }

    // 2. 拦截 URL 加载并探测配置
    private static void hookLoadUrl(final XC_LoadPackage.LoadPackageParam lpparam) {
        XposedHelpers.findAndHookMethod(WebView.class, "loadUrl", String.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                String url = (String) param.args[0];
                if (url == null) return;

                // 核心：加载网页前进行全量基线检查
                checkWebViewSettings((WebView) param.thisObject, lpparam.packageName);

                if (url.startsWith("file://")) {
                    report(lpparam.packageName, VULN_FILE, "Loading local file: " + url);
                } else if (url.startsWith("javascript:")) {
                    report(lpparam.packageName, VULN_XSS, "Executing Inline JS: " + url);
                } else if (url.startsWith("http://")) {
                    report(lpparam.packageName, VULN_URL, "Insecure HTTP: " + url);
                }
            }
        });
    }

    // 3. 探测外部页面打开逻辑
    private static void hookWebViewClient(final XC_LoadPackage.LoadPackageParam lpparam) {
        XposedHelpers.findAndHookMethod(WebView.class, "setWebViewClient",
                "android.webkit.WebViewClient", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        Object client = param.args[0];
                        if (client == null) return;

                        final String clientName = client.getClass().getName();
                        try {
                            XposedHelpers.findAndHookMethod(client.getClass(), "shouldOverrideUrlLoading",
                                    WebView.class, String.class, new XC_MethodHook() {
                                        @Override
                                        protected void afterHookedMethod(MethodHookParam param) {
                                            String url = (String) param.args[1];
                                            report(lpparam.packageName, VULN_URL, "shouldOverrideUrlLoading in " + clientName + " -> URL: " + url);
                                        }
                                    });
                        } catch (Throwable ignored) {}
                    }
                });
    }

    private static void report(String pkg, String type, String msg) {
        Log.i(TAG, "[" + type + "] " + msg);
        SecurityUtils.reportEvent(pkg, type, msg);
    }
}
