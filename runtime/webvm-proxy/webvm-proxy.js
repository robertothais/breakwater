/**
 * WebVM Proxy Script - Privacy-preserving JSONP interceptor
 * 
 * This script runs in the banking site's context but keeps all parameters
 * client-side using URL fragments. The server never sees sensitive data.
 * 
 * Flow:
 * 1. Extension redirects lx.astxsvc.com/endpoint?params to this script with #endpoint&params
 * 2. We parse fragments (never sent to server) 
 * 3. Send message to extension to handle via WebVM
 * 4. Extension responds and we execute the JSONP callback
 */

(function() {
  'use strict';
  
  console.log('WebVM Proxy: Script loaded');
  
  try {
    // Get the current script's src URL parameters
    const currentScript = document.currentScript;
    
    if (!currentScript || !currentScript.src) {
      console.error('WebVM Proxy: Could not find current script');
      return;
    }
    
    console.log('WebVM Proxy: Script src:', currentScript.src);
    
    // Extract endpoint and params from the original lx.astxsvc.com URL
    const scriptUrl = new URL(currentScript.src);
    let endpoint, queryParams;
    
    if (scriptUrl.hostname === 'lx.astxsvc.com') {
      // Original URL format: https://lx.astxsvc.com:55920/ASTX2/hello?v=3&callback=...
      endpoint = scriptUrl.pathname; // e.g., "/ASTX2/hello"
      queryParams = scriptUrl.search.substring(1); // Remove the "?" and get "v=3&callback=..."
    } else {
      // Redirected URL format: http://localhost:8000/webvm-proxy.js?endpoint=/ASTX2/hello&params=...
      const urlParams = new URLSearchParams(scriptUrl.search);
      endpoint = urlParams.get('endpoint');
      queryParams = urlParams.get('params');
    }
    
    console.log('WebVM Proxy: Parsed params from script src:', { 
      endpoint, 
      queryParams,
      hostname: scriptUrl.hostname
    });
    
    if (!endpoint || !queryParams) {
      console.error('WebVM Proxy: Missing endpoint or params in script URL');
      return;
    }
    
    // Extract callback from the query parameters
    const queryParamsObj = new URLSearchParams(queryParams);
    const callback = queryParamsObj.get('callback');
    
    if (!endpoint || !callback) {
      console.error('WebVM Proxy: Missing required parameters', {endpoint, callback});
      return;
    }
    
    console.log('WebVM Proxy: Extracted parameters', {
      endpoint: endpoint,
      callback: callback,
      note: 'These parameters were never sent to the server!'
    });
    
    // Listen for response from extension
    const handleExtensionResponse = (event) => {
      if (event.data.type === 'WEBVM_ASTX_RESPONSE') {
        console.log('WebVM Proxy: Received response from extension', event.data);
        
        const response = event.data.data;
        if (response.success && callback) {
          try {
            // Execute JSONP callback directly
            console.log(`WebVM Proxy: Executing JSONP callback ${callback}`);
            const callbackFunction = window[callback];
            if (typeof callbackFunction === 'function') {
              callbackFunction(response.data);
              console.log('WebVM Proxy: JSONP callback executed successfully');
            } else {
              console.error(`WebVM Proxy: Callback ${callback} is not a function`);
            }
          } catch (error) {
            console.error('WebVM Proxy: Error executing JSONP callback', error);
          }
        } else {
          console.error('WebVM Proxy: Request failed', response.error);
        }
        
        // Remove listener after handling response
        window.removeEventListener('message', handleExtensionResponse);
      }
    };
    
    // Add response listener
    window.addEventListener('message', handleExtensionResponse);
    
    // Send message to extension  
    window.postMessage({
      type: 'WEBVM_ASTX_REQUEST',
      data: {
        endpoint: endpoint,
        callback: callback,
        params: queryParams // Query parameters for ASTx daemon
      }
    }, '*');
    
    console.log('WebVM Proxy: Message sent to extension, waiting for response');
    
  } catch (error) {
    console.error('WebVM Proxy: Error processing request', error);
  }
})();