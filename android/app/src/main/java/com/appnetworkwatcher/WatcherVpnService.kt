package com.appnetworkwatcher

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ProxyInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream

class WatcherVpnService : VpnService() {
    private var tunnel: ParcelFileDescriptor? = null
    private var relay: Relay? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val host = intent?.getStringExtra("host") ?: "127.0.0.1"
        val port = intent?.getIntExtra("port", 8080) ?: 8080
        startInForeground()
        tunnel?.close()
        val builder = Builder()
            .setSession("App Network Watcher")
            .setMtu(1280)
            .addAddress("10.7.0.1", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
        if (Build.VERSION.SDK_INT >= 29) {
            builder.setHttpProxy(ProxyInfo.buildDirectProxy(host, port))
        }
        val established = builder.establish()
        if (established == null) {
            Log.i(TAG, "VPN_DENIED")
            broadcast(false)
            stopSelf()
            return START_NOT_STICKY
        }
        tunnel = established
        val next = Relay(
            FileInputStream(established.fileDescriptor),
            FileOutputStream(established.fileDescriptor),
            this,
            host,
            port,
        )
        relay = next
        Thread({ next.loop() }, "watcher-relay").start()
        Log.i(TAG, "VPN_READY")
        broadcast(true)
        return START_STICKY
    }

    override fun onRevoke() {
        relay?.stop()
        tunnel?.close()
        broadcast(false)
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        relay?.stop()
        tunnel?.close()
        super.onDestroy()
    }

    private fun broadcast(ready: Boolean) {
        sendBroadcast(
            Intent(ACTION_STATE)
                .setPackage(packageName)
                .putExtra(EXTRA_READY, ready),
        )
    }

    private fun startInForeground() {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) {
            val channel = NotificationChannel(CHANNEL, "VPN", NotificationManager.IMPORTANCE_LOW)
            manager.createNotificationChannel(channel)
        }
        val pending = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(this, CHANNEL)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .setContentTitle("App Network Watcher")
            .setContentText("VPN is on for this device. Captured HTTP goes to your computer.")
            .setContentIntent(pending)
            .build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(1, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(1, notification)
        }
    }

    companion object {
        const val ACTION_STATE = "com.appnetworkwatcher.VPN_STATE"
        const val EXTRA_READY = "ready"
        private const val CHANNEL = "watcher-vpn"
        private const val TAG = "WatcherVpn"
    }
}
