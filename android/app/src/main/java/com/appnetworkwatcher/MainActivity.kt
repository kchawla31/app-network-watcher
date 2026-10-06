package com.appnetworkwatcher

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.security.KeyChain
import android.util.Log
import android.widget.Button
import android.widget.CheckBox
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import java.io.File

class MainActivity : AppCompatActivity() {
    private lateinit var banner: TextView
    private lateinit var details: TextView
    private lateinit var approved: CheckBox
    private var vpnReady = false

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            vpnReady = intent?.getBooleanExtra(WatcherVpnService.EXTRA_READY, false) == true
            render()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        banner = findViewById(R.id.banner)
        details = findViewById(R.id.details)
        approved = findViewById(R.id.cert_approved)
        approved.setOnCheckedChangeListener { _, checked ->
            if (checked) {
                Log.i(TAG, "CERT_APPROVED")
            }
            render()
        }
        findViewById<Button>(R.id.start_vpn).setOnClickListener { startVpn() }
        findViewById<Button>(R.id.install_cert).setOnClickListener { installCert() }
        render()
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter(WatcherVpnService.ACTION_STATE)
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(receiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(receiver, filter)
        }
    }

    override fun onStop() {
        super.onStop()
        unregisterReceiver(receiver)
    }

    private fun startVpn() {
        val prepare = VpnService.prepare(this)
        if (prepare != null) {
            startActivityForResult(prepare, REQUEST_VPN)
        } else {
            onActivityResult(REQUEST_VPN, Activity.RESULT_OK, null)
        }
    }

    @Deprecated("Activity result API is enough here and minSdk is 24")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQUEST_VPN) {
            return
        }
        if (resultCode != Activity.RESULT_OK) {
            banner.text = "VPN was not approved. Traffic is not being intercepted."
            return
        }
        val service = Intent(this, WatcherVpnService::class.java)
            .putExtra("host", host())
            .putExtra("port", port())
        ContextCompat.startForegroundService(this, service)
        banner.text = "Waiting for the VPN to come up."
    }

    private fun installCert() {
        val source = File("/sdcard/Download/app-network-watcher-ca.crt")
        if (!source.isFile) {
            banner.text = "The CA file is not on the device yet. Push it from the desktop app first."
            return
        }
        val install = KeyChain.createInstallIntent()
        install.putExtra(KeyChain.EXTRA_CERTIFICATE, source.readBytes())
        install.putExtra(KeyChain.EXTRA_NAME, "App Network Watcher")
        Log.i(TAG, "CERT_PROMPT_SHOWN")
        startActivity(install)
    }

    private fun render() {
        val active = vpnReady && approved.isChecked
        banner.text = if (active) {
            "VPN and CA are active. This device is sending the listed TCP ports to the desktop proxy."
        } else {
            "VPN and CA are not both active. Approve the VPN system dialog and the certificate prompt."
        }
        details.text = """
            host ${host()}
            port ${port()}
            fingerprint ${fingerprint()}

            TCP 80, 443, 8000, 8001, 8080, 8888, and 9000 are sent to the proxy.
            Other TCP and UDP are forwarded. IPv6 and ICMP are not captured.
            Android 10 and newer also get a process HTTP proxy inside the VPN.
            Apps that pin certificates will fail. This app does not bypass pinning.
            Release builds trust a user CA only when the app opts in, or when this CA is in the system store on an emulator or an already-rooted device.
        """.trimIndent()
    }

    private fun host(): String = intent.getStringExtra("host") ?: "127.0.0.1"

    private fun port(): Int = intent.getIntExtra("port", 8080)

    private fun fingerprint(): String = intent.getStringExtra("fp") ?: ""

    companion object {
        private const val TAG = "WatcherVpn"
        private const val REQUEST_VPN = 7
    }
}
