import { ModeManager } from "./modes";
import { WEBVM_CONFIG } from "./config";

// Update declarativeNetRequest rules based on current mode
export const updateRedirectRules = async (modeManager: ModeManager) => {
  const mode = modeManager.getMode();

  // Clear all session rules first
  const existingRules = await chrome.declarativeNetRequest.getSessionRules();
  const existingRuleIds = existingRules.map((rule) => rule.id);

  if (mode === "local") {
    const serverUrl = modeManager.getLocalServerUrl();
    console.log(`Setting up local mode redirects to: ${serverUrl}`);

    // Add session rule for local server redirect
    await chrome.declarativeNetRequest.updateSessionRules({
      removeRuleIds: existingRuleIds, // Remove any existing session rules
      addRules: [
        {
          id: 1000, // Use different ID for session rules
          priority: 1,
          action: {
            type: "redirect",
            redirect: {
              regexSubstitution: "http://localhost:8080\\1",
            },
          },
          condition: {
            regexFilter: "^https://lx\\.astxsvc\\.com:55920(.*)",
            resourceTypes: ["script"],
          },
        },
      ],
    });
    console.log("Local mode redirect rule activated");
  } else if (mode === "embedded") {
    console.log("Setting up embedded mode (webvm-proxy redirect)");

    // Add redirect rule for embedded mode to webvm-proxy
    await chrome.declarativeNetRequest.updateSessionRules({
      removeRuleIds: existingRuleIds, // Remove any existing session rules
      addRules: [
        {
          id: 2000, // Different ID for embedded mode
          priority: 1,
          action: {
            type: "redirect",
            redirect: {
              regexSubstitution: `${WEBVM_CONFIG.PROXY_URL}?endpoint=\\1&params=\\2`,
            },
          },
          condition: {
            regexFilter: "^https://lx\\.astxsvc\\.com:55920(.*?)\\?(.*)$",
            resourceTypes: ["script"],
          },
        },
      ],
    });
    console.log("Embedded mode webvm-proxy redirect rule activated");
  }
};
