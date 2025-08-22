// Central configuration for WebVM domain and resources
export const WEBVM_CONFIG = {
  // Change this to your actual domain where webvm-proxy.js and filesystem are hosted
  DOMAIN: "http://localhost:8000",

  get PROXY_URL() {
    return `${this.DOMAIN}/webvm-proxy.js`;
  },
} as const;
