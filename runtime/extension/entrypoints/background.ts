import { ModeManager } from "../lib/modes";
import { HandlerFactory, type ASTxHandler } from "../lib/handlers";
import { EmbeddedWebVMHandler } from "../lib/webvm-handler";
import { MessageHandlers } from "../lib/message-handlers";
import { updateRedirectRules } from "../lib/redirect-rules";

export default defineBackground(() => {
  console.log("ASTx Bridge: Background service worker started (MV3)");


  let modeManager: ModeManager;
  let currentHandler: ASTxHandler;
  let embeddedWebVMHandler: EmbeddedWebVMHandler;
  let messageHandlers: MessageHandlers;


  // Initialize mode system
  const initializeModeSystem = async () => {
    modeManager = new ModeManager();
    await modeManager.loadConfig();

    // Initialize WebVM handler for embedded mode
    embeddedWebVMHandler = new EmbeddedWebVMHandler();

    // Auto-detect best mode on startup
    currentHandler = await HandlerFactory.createBest(modeManager);
    const modeName = currentHandler ? currentHandler.getName() : modeManager.getMode();
    console.log(`ASTx mode initialized: ${modeName}`);


    // Initialize message handlers
    messageHandlers = new MessageHandlers(
      modeManager,
      currentHandler,
      embeddedWebVMHandler
    );

    // Update redirect rules based on mode
    await updateRedirectRules(modeManager);
  };

  // Handle requests from content scripts
  chrome.runtime.onMessage.addListener(
    async (message, sender, sendResponse) => {
      if (message.type === "ASTX_REQUEST") {
        const response = await messageHandlers.handleASTxRequest(message);
        sendResponse(response);
        return true;
      }

      if (message.type === "CHANGE_MODE") {
        const response = await messageHandlers.handleChangeMode(message);
        sendResponse(response);
        return true;
      }

      if (message.type === "WEBVM_CALL") {
        const response = await messageHandlers.handleWebVMCall(message);
        sendResponse(response);
        return true;
      }

      if (message.type === "GET_STATUS") {
        const response = messageHandlers.handleGetStatus();
        sendResponse(response);
        return true;
      }
    }
  );

  // Debug logging for MV3
  if (chrome.declarativeNetRequest.onRuleMatchedDebug) {
    chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
      console.log("RULE-DEBUG: Rule matched:", {
        rule: info.rule,
        request: info.request,
        timestamp: Date.now(),
      });
    });
  }

  // Log navigation events
  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.url.includes("localhost:8080")) {
      console.log("NAV-DEBUG: Redirected to local proxy:", {
        url: details.url,
        frameId: details.frameId,
        tabId: details.tabId,
      });
    }
  });

  chrome.webNavigation.onErrorOccurred.addListener((details) => {
    if (
      details.url.includes("localhost:8080") ||
      details.url.includes("lx.astxsvc.com")
    ) {
      console.log("NAV-DEBUG: Navigation error:", {
        url: details.url,
        error: details.error,
      });
    }
  });

  // Initialize on startup
  initializeModeSystem().catch(console.error);
});
