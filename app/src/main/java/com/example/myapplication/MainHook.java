package com.example.myapplication;

import android.util.Log;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class MainHook implements IXposedHookLoadPackage {

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {

        Log.e("SEC_SCAN", "Loaded: " + lpparam.packageName);

        if (lpparam.packageName.equals("com.android.systemui")) return;

        // 只检测99driver
        if (!lpparam.packageName.equals("com.app99.driver")) return;

        WebViewHook.init(lpparam);
    }
}