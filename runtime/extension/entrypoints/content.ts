export default defineContentScript({
  matches: [
    "*://*.shinhan.com/*",
    // Add other Korean banking sites as needed
  ],
  main() {
    console.log("ASTx Bridge: Content script loaded on:", window.location.href);

    let currentMode: "local" | "embedded" = "local";

    // Get current mode from background
    const initializeMode = async () => {
      try {
        const response = await chrome.runtime.sendMessage({
          type: "GET_STATUS",
        });
        currentMode = response.mode;
        console.log(`Content script mode: ${currentMode}`);

        if (currentMode === "embedded") {
          setupEmbeddedModeInterception();
        }
      } catch (error) {
        console.error("Failed to get mode status:", error);
      }
    };

    // Setup embedded mode (no-op for now)
    const setupEmbeddedModeInterception = () => {
      console.log("EMBEDDED: Embedded mode active (no interception)");
      // Do nothing - let requests fail naturally
    };

    // Initialize when DOM is ready
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", initializeMode);
    } else {
      initializeMode();
    }

    // Listen for WebVM ASTx requests from webvm-proxy.js
    window.addEventListener("message", async (event) => {
      if (event.data.type === "WEBVM_ASTX_REQUEST") {
        console.log("Content script: Received WebVM ASTx request", event.data);

        const { endpoint, callback, params } = event.data.data;

        try {
          // Forward to background script for WebVM processing
          const response = await chrome.runtime.sendMessage({
            type: "WEBVM_CALL",
            payload: {
              endpoint: endpoint,
              params: params,
            },
          });

          console.log("Content script: Received WebVM response", response);

          // Send response back to webvm-proxy.js
          window.postMessage(
            {
              type: "WEBVM_ASTX_RESPONSE",
              data: response,
            },
            "*"
          );
        } catch (error) {
          console.error("Content script: Error handling WebVM request", error);

          // Send error response back to webvm-proxy.js
          window.postMessage(
            {
              type: "WEBVM_ASTX_RESPONSE",
              data: {
                success: false,
                error: error.message,
              },
            },
            "*"
          );
        }
      }
    });

    // Listen for mode changes from background
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.type === "MODE_CHANGED") {
        currentMode = message.mode;
        console.log(`Content script mode changed to: ${currentMode}`);

        if (currentMode === "embedded") {
          setupEmbeddedModeInterception();
        }

        sendResponse({ success: true });
        return true;
      }
    });
  },
});
