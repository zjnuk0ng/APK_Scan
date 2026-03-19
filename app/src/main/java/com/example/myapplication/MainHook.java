package com.example.myapplication;

import android.app.Application;
import android.content.Context;
import android.util.Log;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class MainHook implements IXposedHookLoadPackage {

    private static final String TAG = "SEC_SCAN";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {

        if (lpparam.packageName.equals("com.example.myapplication")) return;
        if (lpparam.packageName.equals("com.android.systemui")) return;

        // 这里的包名可以根据需要修改，或者去掉 if 直接 Hook 所有 App
        if (!lpparam.packageName.equals("com.app99.driver")) return;

        Log.i(TAG, "Hooking package: " + lpparam.packageName);

        // 初始化 WebView 监控
        WebViewHook.init(lpparam);
        // 初始化 SDK 识别
        SDKHook.init(lpparam);

        // 采集目标 App 基线信息
        hookApplicationForBaseline(lpparam);
    }

    private void hookApplicationForBaseline(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            XposedHelpers.findAndHookMethod(Application.class, "onCreate", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    Context context = (Context) param.thisObject;
                    if (context != null) {
                        // 使用工具类采集并上报
                        String data = SecurityUtils.collectBaseline(context);
                        Report.reportToBackend(data);
                        Log.i(TAG, "Baseline info reported for: " + context.getPackageName());
                    }
                }
            });
        } catch (Throwable t) {
            Log.e(TAG, "Failed to hook Application.onCreate", t);
        }
    }
}
