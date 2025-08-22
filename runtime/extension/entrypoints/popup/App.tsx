import { useState, useEffect } from "react";
import "./App.css";

interface ExtensionStatus {
  mode: "local" | "embedded";
  handler: string;
  config: any;
}

function App() {
  const [status, setStatus] = useState<ExtensionStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [switching, setSwitching] = useState(false);

  useEffect(() => {
    loadStatus();
  }, []);

  const loadStatus = async () => {
    try {
      const response = await chrome.runtime.sendMessage({ type: "GET_STATUS" });
      setStatus(response);
    } catch (error) {
      console.error("Failed to load status:", error);
    } finally {
      setLoading(false);
    }
  };

  const switchMode = async (newMode: "local" | "embedded") => {
    setSwitching(true);
    try {
      await chrome.runtime.sendMessage({
        type: "CHANGE_MODE",
        mode: newMode,
      });
      await loadStatus(); // Reload status after change
    } catch (error) {
      console.error("Failed to switch mode:", error);
    } finally {
      setSwitching(false);
    }
  };

  if (loading) {
    return (
      <div className="container">
        <h2>🏦 ASTx Bridge</h2>
        <p>Loading...</p>
      </div>
    );
  }

  return (
    <div className="container">
      <h2>🏦 ASTx Bridge</h2>

      <div className="status-section">
        <h3>Current Status</h3>
        <div className="status-item">
          <span className="label">Mode:</span>
          <span className={`mode ${status?.mode}`}>
            {status?.mode === "local" ? "🖥️ Local Server" : "🌐 Embedded"}
          </span>
        </div>
        <div className="status-item">
          <span className="label">Handler:</span>
          <span className="handler">{status?.handler}</span>
        </div>
      </div>

      <div className="mode-section">
        <h3>Mode Selection</h3>
        <div className="mode-buttons">
          <button
            className={`mode-button ${
              status?.mode === "local" ? "active" : ""
            }`}
            onClick={() => switchMode("local")}
            disabled={switching || status?.mode === "local"}
          >
            🖥️ Local Server
            <small>Use Docker container</small>
          </button>

          <button
            className={`mode-button ${
              status?.mode === "embedded" ? "active" : ""
            }`}
            onClick={() => switchMode("embedded")}
            disabled={switching || status?.mode === "embedded"}
          >
            🌐 Embedded
            <small>CheerpX in browser (Beta)</small>
          </button>
        </div>
      </div>

      {switching && (
        <div className="switching-notice">
          <p>⚡ Switching mode...</p>
        </div>
      )}

      <div className="info-section">
        <small>
          {status?.mode === "local"
            ? "Using external Docker container for ASTx processing"
            : "Using embedded CheerpX for browser-native ASTx processing"}
        </small>
      </div>
    </div>
  );
}

export default App;
