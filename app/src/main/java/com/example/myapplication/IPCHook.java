package com.example.myapplication;

import android.content.Context;
import android.net.Uri;
import android.os.Binder;
import android.util.Log;

import java.util.Arrays;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class IPCHook {

    private static final String TAG = "SEC_SCAN";

    // 类型
    private static final String IPC_QUERY = "IPC_QUERY";
    private static final String IPC_INSERT = "IPC_INSERT";
    private static final String IPC_UPDATE = "IPC_UPDATE";
    private static final String IPC_DELETE = "IPC_DELETE";
    private static final String IPC_PERMISSION = "IPC_PERMISSION";
    private static final String IPC_RISK = "IPC_UNAUTHORIZED";

    private static final ThreadLocal<IPCContext> ipcContext = new ThreadLocal<>();

    public static void init(XC_LoadPackage.LoadPackageParam lpparam) {
        hookTransport(lpparam);
        hookPermissionCheck(lpparam);
    }


    // IPC上下文
    static class IPCContext {
        String callerPkg;
        int callerUid;
        String uri;
        boolean permissionChecked = false;
    }


    // 核心：Hook Transport（兼容所有 Android 版本）
    private static void hookTransport(final XC_LoadPackage.LoadPackageParam lpparam) {

        try {
            Class<?> transportClass = XposedHelpers.findClass(
                    "android.content.ContentProvider$Transport",
                    lpparam.classLoader
            );

            hookMethod(transportClass, "query", IPC_QUERY, lpparam);
            hookMethod(transportClass, "insert", IPC_INSERT, lpparam);
            hookMethod(transportClass, "update", IPC_UPDATE, lpparam);
            hookMethod(transportClass, "delete", IPC_DELETE, lpparam);

        } catch (Throwable t) {
            Log.e(TAG, "Hook Transport failed: " + t.getMessage());
        }
    }

    private static void hookMethod(Class<?> clazz, String methodName, String type,
                                   XC_LoadPackage.LoadPackageParam lpparam) {

        XposedBridge.hookAllMethods(clazz, methodName, new XC_MethodHook() {

            @Override
            protected void beforeHookedMethod(MethodHookParam param) {

                IPCContext ctx = new IPCContext();

                Uri uri = null;

                // 兼容不同参数签名
                for (Object arg : param.args) {
                    if (arg instanceof Uri) {
                        uri = (Uri) arg;
                        break;
                    }
                }

                int uid = Binder.getCallingUid();

                ctx.callerUid = uid;
                ctx.uri = (uri != null) ? uri.toString() : "";
                ctx.callerPkg = getPackageNameByUidSafe(uid);

                ipcContext.set(ctx);

                report(lpparam.packageName, type,
                        "IPC " + methodName +
                                " -> uri=" + ctx.uri +
                                " | caller=" + ctx.callerPkg +
                                " | uid=" + uid);
            }

            @Override
            protected void afterHookedMethod(MethodHookParam param) {

                IPCContext ctx = ipcContext.get();
                if (ctx == null) return;

                // 过滤系统调用
                if (ctx.callerUid < 10000) {
                    ipcContext.remove();
                    return;
                }

                boolean isSelf = ctx.callerPkg.contains(param.thisObject.getClass().getName());

                // 核心检测逻辑（低误报版）
                if (!isSelf &&
                        !ctx.permissionChecked &&
                        isSensitive(ctx.uri)) {

                    report(lpparam.packageName, IPC_RISK,
                            "UNAUTHORIZED IPC -> uri=" + ctx.uri +
                                    " | caller=" + ctx.callerPkg);
                }

                ipcContext.remove();
            }
        });
    }


    //  权限检测 Hook
    private static void hookPermissionCheck(final XC_LoadPackage.LoadPackageParam lpparam) {

        try {
            XposedHelpers.findAndHookMethod(
                    "android.content.ContextWrapper",
                    lpparam.classLoader,
                    "checkPermission",
                    String.class,
                    int.class,
                    int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {

                            IPCContext ctx = ipcContext.get();
                            if (ctx != null && ctx.callerUid >= 10000) {

                                ctx.permissionChecked = true;

                                String perm = (String) param.args[0];

                                report(lpparam.packageName,
                                        IPC_PERMISSION,
                                        "checkPermission -> " + perm);
                            }
                        }
                    }
            );
        } catch (Throwable ignored) {}

        try {
            XposedHelpers.findAndHookMethod(
                    "android.content.ContextWrapper",
                    lpparam.classLoader,
                    "enforcePermission",
                    String.class,
                    int.class,
                    int.class,
                    String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {

                            IPCContext ctx = ipcContext.get();
                            if (ctx != null && ctx.callerUid >= 10000) {

                                ctx.permissionChecked = true;

                                String perm = (String) param.args[0];

                                report(lpparam.packageName,
                                        IPC_PERMISSION,
                                        "enforcePermission -> " + perm);
                            }
                        }
                    }
            );
        } catch (Throwable ignored) {}
    }

    // UID → 包名
    private static String getPackageNameByUidSafe(int uid) {
        try {
            Object at = XposedHelpers.callStaticMethod(
                    XposedHelpers.findClass("android.app.ActivityThread", null),
                    "currentActivityThread"
            );

            if (at != null) {
                Context context = (Context) XposedHelpers.callMethod(at, "getSystemContext");

                if (context != null) {
                    String[] pkgs = context.getPackageManager().getPackagesForUid(uid);
                    if (pkgs != null && pkgs.length > 0) {
                        return Arrays.toString(pkgs);
                    }
                }
            }
        } catch (Throwable ignored) {}

        return "uid=" + uid;
    }

    // 过滤器  先关闭！！！
    private static boolean isSensitive(String uri) {
        if (uri == null) return false;

        uri = uri.toLowerCase();

//        return uri.contains("user") ||
//                uri.contains("account") ||
//                uri.contains("token") ||
//                uri.contains("auth") ||
//                uri.contains("data") ||
//                uri.contains("info");
        return true;
    }


    private static void report(String pkg, String type, String msg) {
        Log.i(TAG, "[" + type + "] " + msg);
        Report.reportEvent(pkg, type, msg);
    }
}