import type { ModeManager } from "./modes";

export interface ASTxRequest {
  url: string;
  endpoint: string;
  params: URLSearchParams;
  callback?: string;
}

export interface ASTxResponse {
  success: boolean;
  data: any;
  error?: string;
}

export abstract class ASTxHandler {
  constructor(protected modeManager: ModeManager) {}

  abstract handleRequest(request: ASTxRequest): Promise<ASTxResponse>;
  abstract isAvailable(): Promise<boolean>;
  abstract getName(): string;
}

export class LocalServerHandler extends ASTxHandler {
  getName(): string {
    return "Local Server";
  }

  async isAvailable(): Promise<boolean> {
    try {
      const baseUrl = this.modeManager.getLocalServerUrl();
      // Try the actual ASTx endpoint that exists
      const response = await fetch(`${baseUrl}/ASTX2/hello`, {
        method: "GET",
        signal: AbortSignal.timeout(2000),
      });
      // Accept any response (including errors) as proof the server is running
      return true;
    } catch {
      return false;
    }
  }

  async handleRequest(request: ASTxRequest): Promise<ASTxResponse> {
    try {
      const baseUrl = this.modeManager.getLocalServerUrl();
      const fullUrl = `${baseUrl}${
        request.endpoint
      }?${request.params.toString()}`;

      console.log("LOCAL-MODE: Requesting:", fullUrl);

      const response = await fetch(fullUrl, {
        method: "GET",
        signal: AbortSignal.timeout(5000),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.text();
      console.log("LOCAL-MODE: Response:", data);

      return {
        success: true,
        data: data,
      };
    } catch (error) {
      console.error("LOCAL-MODE: Error:", error);
      return {
        success: false,
        data: null,
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }
}

// EmbeddedHandler removed - embedded mode uses EmbeddedWebVMHandler directly

export class HandlerFactory {
  static create(modeManager: ModeManager): ASTxHandler | null {
    const mode = modeManager.getMode();

    switch (mode) {
      case "local":
        return new LocalServerHandler(modeManager);
      case "embedded":
        // Embedded mode uses EmbeddedWebVMHandler directly, not this handler pattern
        return null;
      default:
        throw new Error(`Unknown mode: ${mode}`);
    }
  }

  static async createBest(modeManager: ModeManager): Promise<ASTxHandler | null> {
    // Try local first
    const localHandler = new LocalServerHandler(modeManager);
    if (await localHandler.isAvailable()) {
      console.log("Using local server mode");
      await modeManager.setMode("local");
      return localHandler;
    }

    // Fall back to embedded
    console.log("Falling back to embedded mode");
    await modeManager.setMode("embedded");
    return null; // Embedded mode uses EmbeddedWebVMHandler
  }
}
