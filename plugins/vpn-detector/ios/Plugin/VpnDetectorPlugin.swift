import Foundation
import Capacitor
import SystemConfiguration

/**
 * VpnDetector (iOS).
 *
 * iOS gives apps no public "is a VPN on" API, so we use two complementary
 * heuristics:
 *
 *   1. CFNetwork's scoped-proxy dictionary: when a VPN is active the
 *      `__SCOPED__` keys contain a tunnel interface (utun/tap/tun/ppp/ipsec).
 *      This is the long-standing, App Store-safe technique.
 *
 *   2. getifaddrs(): enumerate live interfaces and look for tunnel names that
 *      are up. Catches configurations the proxy dictionary misses.
 *
 * A change event is emitted via SCNetworkReachability so the UI can lock the
 * instant the tunnel drops.
 */
@objc(VpnDetectorPlugin)
public class VpnDetectorPlugin: CAPPlugin {

    private var reachability: SCNetworkReachability?
    private let tunnelPrefixes = ["utun", "tap", "tun", "ppp", "ipsec"]

    @objc func isVpnActive(_ call: CAPPluginCall) {
        let result = detect()
        call.resolve([
            "active": result.active,
            "interfaces": result.interfaces
        ])
    }

    @objc func startMonitoring(_ call: CAPPluginCall) {
        guard reachability == nil else {
            call.resolve()
            return
        }
        var zero = sockaddr()
        zero.sa_len = UInt8(MemoryLayout<sockaddr>.size)
        zero.sa_family = sa_family_t(AF_INET)

        guard let reach = SCNetworkReachabilityCreateWithAddress(nil, &zero) else {
            call.resolve()
            return
        }
        self.reachability = reach

        var context = SCNetworkReachabilityContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil, release: nil, copyDescription: nil
        )

        let callback: SCNetworkReachabilityCallBack = { (_, _, info) in
            guard let info = info else { return }
            let plugin = Unmanaged<VpnDetectorPlugin>.fromOpaque(info).takeUnretainedValue()
            let status = plugin.detect()
            plugin.notifyListeners("vpnStatusChanged", data: [
                "active": status.active,
                "interfaces": status.interfaces
            ])
        }

        SCNetworkReachabilitySetCallback(reach, callback, &context)
        SCNetworkReachabilitySetDispatchQueue(reach, DispatchQueue.main)
        call.resolve()
    }

    @objc func stopMonitoring(_ call: CAPPluginCall) {
        if let reach = reachability {
            SCNetworkReachabilitySetCallback(reach, nil, nil)
            SCNetworkReachabilitySetDispatchQueue(reach, nil)
        }
        reachability = nil
        call.resolve()
    }

    // MARK: - Detection

    private func detect() -> (active: Bool, interfaces: [String]) {
        var active = false
        var found: [String] = []

        // Signal 1: scoped proxy keys.
        if let cfDict = CFNetworkCopySystemProxySettings()?.takeRetainedValue(),
           let dict = cfDict as? [String: Any],
           let scoped = dict["__SCOPED__"] as? [String: Any] {
            for key in scoped.keys {
                if tunnelPrefixes.contains(where: { key.hasPrefix($0) }) {
                    active = true
                    found.append(key)
                }
            }
        }

        // Signal 2: live interfaces via getifaddrs.
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        if getifaddrs(&ifaddr) == 0 {
            var ptr = ifaddr
            while ptr != nil {
                if let addr = ptr?.pointee {
                    let name = String(cString: addr.ifa_name)
                    let flags = Int32(addr.ifa_flags)
                    let isUp = (flags & IFF_UP) == IFF_UP
                    if isUp && tunnelPrefixes.contains(where: { name.hasPrefix($0) }) {
                        active = true
                        if !found.contains(name) { found.append(name) }
                    }
                }
                ptr = ptr?.pointee.ifa_next
            }
            freeifaddrs(ifaddr)
        }

        return (active, found)
    }
}
