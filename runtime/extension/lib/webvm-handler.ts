import { WEBVM_CONFIG } from "./config";

// WebVM Handler for embedded mode using tab communication
export class EmbeddedWebVMHandler {
  async sendRequestToWebVMTab(payload: { endpoint: string; params: string }): Promise<any> {
    try {
      console.log("EmbeddedWebVMHandler: Looking for WebVM tabs...");

      // Find all tabs with WebVM domain
      const tabs = await chrome.tabs.query({
        url: `${WEBVM_CONFIG.DOMAIN}/*`
      });

      if (tabs.length === 0) {
        return {
          success: false,
          error: "No WebVM tab found. Please open a tab to " + WEBVM_CONFIG.DOMAIN,
          data: null,
        };
      }

      console.log(`EmbeddedWebVMHandler: Found ${tabs.length} WebVM tab(s), using first one`);
      const webvmTab = tabs[0];

      // Generate unique request ID for response matching
      const requestId = `webvm_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

      return new Promise((resolve, reject) => {
        // Set up timeout
        const timeout = setTimeout(() => {
          reject(new Error("WebVM request timeout"));
        }, 30000); // 30 second timeout

        // Send request and listen for response via executeScript
        chrome.scripting.executeScript({
          target: { tabId: webvmTab.id! },
          func: (payload: any, requestId: string) => {
            // Send request
            window.postMessage({
              type: 'WEBVM_REQUEST_FROM_EXTENSION',
              payload: payload,
              requestId: requestId
            }, '*');

            // Listen for response
            const responseListener = (event: any) => {
              if (event.data.type === 'WEBVM_RESPONSE_TO_EXTENSION' && event.data.requestId === requestId) {
                window.removeEventListener('message', responseListener);
                // Return response to extension via the script result
                return event.data.response;
              }
            };

            window.addEventListener('message', responseListener);

            // Return a promise that resolves when we get the response
            return new Promise((resolve) => {
              const responseListener = (event: any) => {
                if (event.data.type === 'WEBVM_RESPONSE_TO_EXTENSION' && event.data.requestId === requestId) {
                  window.removeEventListener('message', responseListener);
                  resolve(event.data.response);
                }
              };
              window.addEventListener('message', responseListener);
            });
          },
          args: [payload, requestId]
        }).then((results) => {
          clearTimeout(timeout);
          console.log("EmbeddedWebVMHandler: executeScript results:", results);
          console.log("EmbeddedWebVMHandler: executeScript result[0]:", results[0]);
          console.log("EmbeddedWebVMHandler: executeScript result[0].result:", results[0].result);
          resolve(results[0].result);
        }).catch((error) => {
          clearTimeout(timeout);
          console.error("EmbeddedWebVMHandler: executeScript error:", error);
          reject(error);
        });
      });
    } catch (error) {
      console.error("EmbeddedWebVMHandler: Error communicating with WebVM tab", error);
      return {
        success: false,
        error: error instanceof Error ? error.message : "Failed to communicate with WebVM tab",
        data: null,
      };
    }
  }
}