import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.akira.remotecontrol',
  appName: 'تحكم بعيد',
  webDir: 'www',
  server: {
    // The existing authenticated web client remains the single source of truth.
    // The native shell loads it over HTTPS; no agent/server changes are required.
    url: 'https://remote-control-by-akira.onrender.com',
    cleartext: false,
    allowNavigation: ['remote-control-by-akira.onrender.com']
  },
  android: {
    allowMixedContent: false
  }
};

export default config;
