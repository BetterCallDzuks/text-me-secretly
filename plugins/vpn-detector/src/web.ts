import { WebPlugin } from '@capacitor/core';

import type { VpnDetectorPlugin, VpnStatus } from './definitions';

/**
 * Browser fallback. A web page CANNOT read network interfaces, so real VPN
 * detection is impossible here. We fail CLOSED by default (report inactive) so
 * the app's VPN gate stays strict; set `window.__TMS_DEV_ALLOW_NO_VPN__ = true`
 * in a dev console to bypass while working on the UI in a desktop browser.
 */
export class VpnDetectorWeb extends WebPlugin implements VpnDetectorPlugin {
  async isVpnActive(): Promise<VpnStatus> {
    const devBypass =
      typeof window !== 'undefined' &&
      (window as unknown as Record<string, unknown>).__TMS_DEV_ALLOW_NO_VPN__ === true;
    return { active: devBypass, interfaces: [] };
  }

  async startMonitoring(): Promise<void> {
    /* no-op on web */
  }

  async stopMonitoring(): Promise<void> {
    /* no-op on web */
  }
}
