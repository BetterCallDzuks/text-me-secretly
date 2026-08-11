#import <Foundation/Foundation.h>
#import <Capacitor/Capacitor.h>

// Bridges the Swift plugin to Capacitor's runtime and declares its JS methods.
CAP_PLUGIN(VpnDetectorPlugin, "VpnDetector",
    CAP_PLUGIN_METHOD(isVpnActive, CAPPluginReturnPromise);
    CAP_PLUGIN_METHOD(startMonitoring, CAPPluginReturnPromise);
    CAP_PLUGIN_METHOD(stopMonitoring, CAPPluginReturnPromise);
)
