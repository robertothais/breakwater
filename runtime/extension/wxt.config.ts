import { defineConfig } from "wxt";

// See https://wxt.dev/api/config.html
export default defineConfig({
  modules: ["@wxt-dev/module-react"],
  manifest: {
    name: "ASTx Bridge",
    description: "Bridge extension for Korean banking security software (ASTx)",
    permissions: ["declarativeNetRequest", "webNavigation", "storage"],
    host_permissions: [
      "*://lx.astxsvc.com/*",
      "http://localhost:8080/*",
      "https://cxrtnc.leaningtech.com/*", // For CheerpX CDN
    ],
    commands: {
      _execute_action: {
        suggested_key: {
          default: "Ctrl+Shift+E",
          mac: "Command+Shift+E",
        },
      },
    },
  },
});
