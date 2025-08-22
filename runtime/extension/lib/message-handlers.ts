import { ModeManager } from "./modes";
import { HandlerFactory, type ASTxHandler, type ASTxRequest } from "./handlers";
import { EmbeddedWebVMHandler } from "./webvm-handler";
import { updateRedirectRules } from "./redirect-rules";

export class MessageHandlers {
  private currentHandler: ASTxHandler | null;

  constructor(
    private modeManager: ModeManager,
    currentHandler: ASTxHandler | null,
    private embeddedWebVMHandler: EmbeddedWebVMHandler
  ) {
    this.currentHandler = currentHandler;
  }

  // Handle ASTX_REQUEST messages
  async handleASTxRequest(message: any): Promise<any> {
    try {
      if (!this.currentHandler) {
        return {
          success: false,
          data: null,
          error: "No handler available for current mode",
        };
      }

      const request: ASTxRequest = {
        url: message.url,
        endpoint: message.endpoint,
        params: new URLSearchParams(message.params),
        callback: message.callback,
      };

      const response = await this.currentHandler.handleRequest(request);
      return response;
    } catch (error) {
      console.error("Error handling ASTx request:", error);
      return {
        success: false,
        data: null,
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  // Handle CHANGE_MODE messages
  async handleChangeMode(message: any): Promise<any> {
    try {
      await this.modeManager.setMode(message.mode);
      this.currentHandler = HandlerFactory.create(this.modeManager);
      await updateRedirectRules(this.modeManager);

      console.log(`Switched to mode: ${this.currentHandler.getName()}`);
      return { success: true };
    } catch (error) {
      console.error("Error changing mode:", error);
      return {
        success: false,
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  // Handle WEBVM_CALL messages
  async handleWebVMCall(message: any): Promise<any> {
    try {
      console.log("Background: Handling WebVM call", message.payload);

      // Use embedded WebVM via tab communication when in embedded mode
      if (this.modeManager.getMode() === "embedded") {
        return await this.embeddedWebVMHandler.sendRequestToWebVMTab(message.payload);
      } else {
        // Fall back to regular handler for local mode
        const request: ASTxRequest = {
          url: `https://lx.astxsvc.com:55920${message.payload.endpoint}?${message.payload.params}`,
          endpoint: message.payload.endpoint,
          params: new URLSearchParams(message.payload.params),
          callback: "", // Not needed for background processing
        };
        const response = await this.currentHandler.handleRequest(request);
        return response;
      }
    } catch (error) {
      console.error("Background: Error handling WebVM call", error);
      return {
        success: false,
        data: null,
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }


  // Handle GET_STATUS messages
  handleGetStatus(): any {
    return {
      mode: this.modeManager.getMode(),
      handler: this.currentHandler ? this.currentHandler.getName() : this.modeManager.getMode(),
      config: this.modeManager.getConfig(),
    };
  }
}