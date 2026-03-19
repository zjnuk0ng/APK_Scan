package com.example.myapplication;

import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedOutputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class Report {
    private static final String TAG = "SEC_REPORT";

    private static final String EVENT_URL = "http://10.0.2.2:8080/report/event";
    private static final String BASELINE_URL = "http://10.0.2.2:8080/report/baseline";

    // 核心：事件队列
    private static final BlockingQueue<String> QUEUE = new LinkedBlockingQueue<>(1000);

    // Worker线程
    static {
        Thread worker = new Thread(() -> {
            while (true) {
                try {
                    String data = QUEUE.take(); // 阻塞等待
                    sendPost(EVENT_URL, data);
                } catch (Exception e) {
                    Log.e(TAG, "Worker Error", e);
                }
            }
        });

        worker.setName("SEC-REPORT-WORKER");
        worker.setDaemon(true);
        worker.start();
    }

    // 对外接口
    public static void reportToBackend(String data) {
        enqueue(BASELINE_URL, data);
    }

    public static void reportEvent(String packageName, String type, String message) {
        try {
            JSONObject json = new JSONObject();
            json.put("packageName", packageName);
            json.put("type", type);
            json.put("message", message);
            json.put("timestamp", System.currentTimeMillis());

            enqueue(EVENT_URL, json.toString());

        } catch (Exception e) {
            Log.e(TAG, "JSON Error", e);
        }
    }


    // 入队（关键：极轻操作）
    private static void enqueue(String url, String data) {
        String payload = url + "|||" + data;

        // 非阻塞写入，避免卡住 Hook
        boolean offered = QUEUE.offer(payload);

        if (!offered) {
            Log.w(TAG, "Queue Full, Dropping Event");
        }
    }

    // 实际网络发送
    private static void sendPost(String targetUrl, String raw) {
        HttpURLConnection conn = null;
        try {
            // 解析 payload
            String[] parts = raw.split("\\|\\|\\|", 2);
            String urlStr = parts[0];
            String data = parts[1];

            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();

            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.setDoOutput(true);

            try (OutputStream os = new BufferedOutputStream(conn.getOutputStream())) {
                byte[] input = data.getBytes(StandardCharsets.UTF_8);
                os.write(input);
                os.flush();
            }

            int code = conn.getResponseCode();
            Log.i(TAG, "Report [" + code + "] -> " + urlStr);

        } catch (Exception e) {
            Log.e(TAG, "Network Error: " + e.getMessage());
        } finally {
            if (conn != null) conn.disconnect();
        }
    }
}

