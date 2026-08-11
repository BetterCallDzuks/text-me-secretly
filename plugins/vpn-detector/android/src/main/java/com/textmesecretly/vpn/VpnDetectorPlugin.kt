package com.textmesecretly.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import com.getcapacitor.JSObject
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.CapacitorPlugin
import org.json.JSONArray
import java.net.NetworkInterface

/**
 * Reports whether the device currently routes through a VPN.
 *
 * Primary signal: NetworkCapabilities.TRANSPORT_VPN on any active network.
 * Secondary signal: presence of a tun/ppp/ipsec interface, which catches some
 * always-on / split-tunnel configurations the transport flag can miss.
 */
@CapacitorPlugin(name = "VpnDetector")
class VpnDetectorPlugin : Plugin() {

    private var callback: ConnectivityManager.NetworkCallback? = null

    @PluginMethod
    fun isVpnActive(call: PluginCall) {
        val status = detect()
        call.resolve(status)
    }

    @PluginMethod
    fun startMonitoring(call: PluginCall) {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        // Only register once.
        if (callback == null) {
            val request = NetworkRequest.Builder().build()
            val cb = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) = emit()
                override fun onLost(network: Network) = emit()
                override fun onCapabilitiesChanged(
                    network: Network,
                    caps: NetworkCapabilities
                ) = emit()

                private fun emit() {
                    notifyListeners("vpnStatusChanged", detect())
                }
            }
            cm.registerNetworkCallback(request, cb)
            callback = cb
        }
        call.resolve()
    }

    @PluginMethod
    fun stopMonitoring(call: PluginCall) {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        callback?.let {
            try {
                cm.unregisterNetworkCallback(it)
            } catch (_: Exception) {
            }
        }
        callback = null
        call.resolve()
    }

    override fun handleOnDestroy() {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        callback?.let {
            try {
                cm.unregisterNetworkCallback(it)
            } catch (_: Exception) {
            }
        }
        callback = null
    }

    private fun detect(): JSObject {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        var active = false
        val ifaces = JSONArray()

        // Signal 1: TRANSPORT_VPN across all networks.
        try {
            for (network in cm.allNetworks) {
                val caps = cm.getNetworkCapabilities(network) ?: continue
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    active = true
                }
            }
        } catch (_: Exception) {
        }

        // Signal 2: tunnel-like interfaces that are up.
        try {
            val en = NetworkInterface.getNetworkInterfaces()
            while (en != null && en.hasMoreElements()) {
                val ni = en.nextElement()
                val name = ni.name?.lowercase() ?: continue
                val looksTunnel = name.startsWith("tun") ||
                    name.startsWith("ppp") ||
                    name.startsWith("ipsec") ||
                    name.startsWith("utun")
                if (looksTunnel && ni.isUp) {
                    active = true
                    ifaces.put(ni.name)
                }
            }
        } catch (_: Exception) {
        }

        val out = JSObject()
        out.put("active", active)
        out.put("interfaces", ifaces)
        return out
    }
}
