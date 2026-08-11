export interface VpnStatus {
  /** True when the OS reports an active VPN transport / tunnel interface. */
  active: boolean;
  /** Interface names that looked like a tunnel (diagnostic only). */
  interfaces?: string[];
}

export interface VpnDetectorPlugin {
  /** One-shot check of the current VPN state. */
  isVpnActive(): Promise<VpnStatus>;

  /**
   * Begin emitting `vpnStatusChanged` events whenever connectivity changes.
   * Use this so the UI can lock instantly the moment a VPN drops.
   */
  startMonitoring(): Promise<void>;

  /** Stop emitting change events. */
  stopMonitoring(): Promise<void>;

  addListener(
    eventName: 'vpnStatusChanged',
    listenerFunc: (status: VpnStatus) => void
  ): Promise<{ remove: () => Promise<void> }>;
}
