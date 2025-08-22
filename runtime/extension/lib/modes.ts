export type ASTxMode = "local" | "embedded";

export interface ModeConfig {
  mode: ASTxMode;
  localServer?: {
    host: string;
    port: number;
    protocol: "http" | "https";
  };
  embedded?: {
    enabled: boolean;
    // Future CheerpX config will go here
  };
}

export const DEFAULT_CONFIG: ModeConfig = {
  mode: "local",
  localServer: {
    host: "localhost",
    port: 8080,
    protocol: "http",
  },
  embedded: {
    enabled: false,
  },
};

export class ModeManager {
  private config: ModeConfig = DEFAULT_CONFIG;

  async loadConfig(): Promise<ModeConfig> {
    try {
      const stored = await chrome.storage.sync.get(["astxMode"]);
      if (stored.astxMode) {
        this.config = { ...DEFAULT_CONFIG, ...stored.astxMode };
      }
    } catch (error) {
      console.warn("Failed to load ASTx mode config:", error);
    }
    return this.config;
  }

  async setMode(mode: ASTxMode): Promise<void> {
    this.config.mode = mode;
    await this.saveConfig();
  }

  async updateConfig(updates: Partial<ModeConfig>): Promise<void> {
    this.config = { ...this.config, ...updates };
    await this.saveConfig();
  }

  private async saveConfig(): Promise<void> {
    await chrome.storage.sync.set({ astxMode: this.config });
  }

  getConfig(): ModeConfig {
    return this.config;
  }

  getMode(): ASTxMode {
    return this.config.mode;
  }

  getLocalServerUrl(): string {
    const { host, port, protocol } = this.config.localServer!;
    return `${protocol}://${host}:${port}`;
  }

  async detectBestMode(): Promise<ASTxMode> {
    // Try to detect if local server is available
    if (await this.isLocalServerAvailable()) {
      return "local";
    }

    // Fall back to embedded mode
    return "embedded";
  }

  private async isLocalServerAvailable(): Promise<boolean> {
    try {
      const url = this.getLocalServerUrl();
      const response = await fetch(`${url}/ASTX2/hello`, {
        method: "GET",
        signal: AbortSignal.timeout(2000), // 2 second timeout
      });
      // Accept any response as proof the server is running
      return true;
    } catch {
      return false;
    }
  }
}
