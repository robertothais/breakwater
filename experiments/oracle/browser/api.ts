import {
  type HelloResponse,
  type SetCertResponse,
  type PclogResponse,
} from "../shared/types";

declare global {
  interface Window {
    [key: string]: (data: any) => void;
  }
}

interface PclogConfig {
  alg: number;
  server: string;
  norsa: number;
  uniq: string;
  utime: number | "now" | null;
  ipaddr: string;
  opt: string;
}

class ConnectionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConnectionError";
  }
}

// Op response types
interface Op47a3Response {
  pem: string;
}

interface Op9f21Response {
  success: boolean;
  key?: string;
  innerData?: string;
  innerSalt?: number;
  error?: string;
}

const API_BASE = "http://localhost:8080/ASTX2";

function jsonp<T = any>(url: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const cb = "cb" + Math.floor(Math.random() * 1e9);
    const s = document.createElement("script");
    window[cb] = (data) => {
      try {
        resolve(data);
      } finally {
        delete window[cb];
        s.remove();
      }
    };
    s.onerror = (e) => {
      delete window[cb];
      s.remove();
      reject(new ConnectionError("Connection failed. Is ASTx running?"));
    };
    s.src =
      url +
      (url.includes("?") ? "&" : "?") +
      "callback=" +
      cb +
      "&_=" +
      Date.now();
    document.body.appendChild(s);
  });
}

export async function callHello(): Promise<HelloResponse> {
  return jsonp<HelloResponse>(`${API_BASE}/hello`);
}

export async function callSetCert(
  setCertBlob: string
): Promise<SetCertResponse> {
  const url = `${API_BASE}/set_cert?v=3&step=1&cert=${setCertBlob}&pageid=${Date.now()}`;
  return jsonp<SetCertResponse>(url);
}

export async function callGetPclog(
  config: PclogConfig
): Promise<PclogResponse> {
  const utimeValue =
    config.utime === "now" || config.utime == null
      ? Math.floor(Date.now() / 1000)
      : Number(config.utime);

  const url =
    `${API_BASE}/get_pclog` +
    `?v=3&ver=1&alg=${config.alg}` +
    `&svr=${encodeURIComponent(config.server)}` +
    `&norsa=${config.norsa}` +
    `&uniq=${config.uniq}` +
    `&utime=${utimeValue}` +
    `&nlog=1&ipaddr=${encodeURIComponent(config.ipaddr)}` +
    `&pageid=${Date.now()}` +
    `&opt=${encodeURIComponent(config.opt)}`;

  return jsonp<PclogResponse>(url);
}

export async function callOp(
  opcode: "47a3",
  data: HelloResponse
): Promise<Op47a3Response>;
export async function callOp(
  opcode: "9f21",
  data: PclogResponse
): Promise<Op9f21Response>;
export async function callOp(opcode: string, data: any): Promise<any>;

export async function callOp(opcode: string, data: any) {
  const response = await fetch(`/op/${opcode}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ data }),
  });

  if (!response.ok) {
    // Don't try to parse error details - just use status code
    throw new Error(`Operation failed: HTTP ${response.status}`);
  }

  return response.json();
}
