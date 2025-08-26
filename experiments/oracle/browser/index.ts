import Alpine from "alpinejs";
import { callHello, callSetCert, callGetPclog, callOp } from "./api";
import {
  type HelloResponse,
  type SetCertResponse,
  type PclogResponse,
} from "../shared/types.js";

interface Results {
  // ASTx Responses
  hello?: HelloResponse;
  setCert?: SetCertResponse;
  pclog?: PclogResponse;
  // Oracle outputs
  pem?: string;
  profile?: Record<string, string>;
  // Error
  error?: Error;
}

const DEFAULT_CONFIG = {
  alg: 0, // 0 = plain packaging; 1 = encrypted packaging
  norsa: 1, // (used only when alg=1/2) 0 = RSA+AES, 1 = AES-only
  server: "shinhanbank",
  uniq: "E89BFFA185B19806C3C608AED9D0329938F0344C998C6696D6020156DD0BB57D",
  ipaddr: "127.0.0.1",
  opt: "",
  utime: 100,
  setCertBlob:
    "s7nuorznq7z82i_z2PzG2T_3mR0TrPYcm7EH2rWsNBwED3wYGTexlvuprcz32rGp6rnoocm_26ev6e_GoPGpAv-X6d_oz_6wkcN7Gvexo30Qd7nric0zGvvKdrGQqvnrrdGcD3zkdiYNqvnv2cYzG3zId6GGz_mg2cuzr7nxG6_NGVYir6_5Gv_K2erErQG6leNWN3niqrnorcm_Nnev6e_GGvGpmfY0GBEnLrm3m6ewGj60q7z826zumPGGirY5AnYusR0BLPWprr6s2e_pG3mjG6ppGvz826_t2BmjGrupdfN8AveLL6zR2PEsid-PL70nre0pk8ek6vJPz3YcAfzOSPSXzv0ELRGO27_527GfScYp6ohCGep0d80ckrIPqRGpArhIoj_DzshKq7_YGQrIAjeylvEcDPPnq3YDS8uC5Peal2Y2D8NKoceOzvGI2R6Yod0MNvG_SeLPLrvIzPW9LiNWoivx5PeeSxztr7zLr7NdqiNHl3KO63hQN_N0o7CTGe-ts70MGrzlonzsmilTSdzw6QGi6vnjAyw_2imEd7WWdvzl63hHGczbzT0LSQ_RXP_OzPwidv03lswXiR6-AiY7r8lXq_YMrrufSjlPkc6TGr_ad768A3GNGsJK5nLI2eGlAj_kq80Xod0l267IA3zlNxNwAd_socpcoeuvlr_dAQ6NdVYC6TzzD_e62RNXmr0_Dx0Wm7hu2dms2j0_djpo2rbxoTm5kiu_r6exkd-WA6VMN6Yiq8082cm_2r_r2rWsNBwEsR0MDrSWmTps26_TG7_pdPzprr6pLxznm__WG7wNm769dcGj2Rw0A3m-2c7MS_pX6vZxDe_W2ibndiY0oRGwk_ZXN3YzzrG7SsCOLd0L2rrni7GTAQvB6PNvlinOr7vtq7NtNvNHSnzpm_NQN3wazRm3zf0pqjmsdBwX5B666BPTm2Y9iQG_znNN5xLtlj6lSB0GAfGdzohM5x6CrRG0oT6tz606LTNzAjuEljNeDBhODR-n2PNgAP0wlyw0ddpfmeNxsj06S8euleNao6_Qoj7I6PYXDrnDmrwBiivt66Y8lfmti7zvz_mYl3zzmvzfldmHDRwrGi65l_rM2RYs2TGu2R7XSrEnkiukod0NSdpWic0nA8mlDr6yzczIoRzoA3hHoRzIrnmRGjmXS_eCoRZMm7NHrRGL2BCMleGIl7eYL6NMzZYoqihGoBZnrQNtiiu2dx0sirWzGOwuk_pp2QlWqcunGcu9SPLxq8LMGvvh92b*",
};

Alpine.data("oracle", () => ({
  config: { ...DEFAULT_CONFIG },
  results: {} as Results,
  loading: false,

  async run() {
    this.loading = true;
    this.results = {};

    try {
      this.results.hello = await callHello();
      const op_1 = await callOp("47a3", this.results.hello);
      this.results.pem = op_1.pem;
      this.results.setCert = await callSetCert(this.config.setCertBlob);
      this.results.pclog = await callGetPclog(this.config);
      const op_2 = await callOp("9f21", this.results.pclog);
    } catch (error) {
      this.results.error =
        error.message || error.toString() || "An unknown error occurred";
    } finally {
      this.loading = false;
    }
  },
}));

// Start Alpine
Alpine.start();

// 	1.	encrypt_gate == 0
// → key=""; later it custom-b64 encodes pwd and server_str only, no RSA.
// 	2.	encrypt_gate != 0 && norsa_flag == 1
// → no RSA; key = encodeWithCustomBase64(per-response ctx, uniq_id).
// 	3.	encrypt_gate != 0 && norsa_flag != 1
// → try RSA path: decode client_key_b64 with the outer b64 (salt=8), wrap in PEM, validate, RSA-encrypt uniq_id; key = custom-b64(per-response ctx, ciphertext).
// Net: data = custom_b64( standard_b64( AES( key=KDF(serverStr), iv=sha256_hex[:16], plaintext=uniqId ) )
