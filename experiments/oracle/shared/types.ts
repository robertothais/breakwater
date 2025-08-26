// ASTX API Response Types
export interface HelloResponse {
  client_public_key: string;
  result: string;
}

export interface SetCertResponse {
  result: string;
}

export interface PclogResponse {
  pclog_data: string;
  result: string;
}
