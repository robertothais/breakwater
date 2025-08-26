#!/usr/bin/env python3

import sys

from crypto_helpers import custom_base64_decode, derive_custom_base64_alphabet

setCertBlob = "s7nuorznq7z82i_z2PzG2T_3mR0TrPYcm7EH2rWsNBwED3wYGTexlvuprcz32rGp6rnoocm_26ev6e_GoPGpAv-X6d_oz_6wkcN7Gvexo30Qd7nric0zGvvKdrGQqvnrrdGcD3zkdiYNqvnv2cYzG3zId6GGz_mg2cuzr7nxG6_NGVYir6_5Gv_K2erErQG6leNWN3niqrnorcm_Nnev6e_GGvGpmfY0GBEnLrm3m6ewGj60q7z826zumPGGirY5AnYusR0BLPWprr6s2e_pG3mjG6ppGvz826_t2BmjGrupdfN8AveLL6zR2PEsid-PL70nre0pk8ek6vJPz3YcAfzOSPSXzv0ELRGO27_527GfScYp6ohCGep0d80ckrIPqRGpArhIoj_DzshKq7_YGQrIAjeylvEcDPPnq3YDS8uC5Peal2Y2D8NKoceOzvGI2R6Yod0MNvG_SeLPLrvIzPW9LiNWoivx5PeeSxztr7zLr7NdqiNHl3KO63hQN_N0o7CTGe-ts70MGrzlonzsmilTSdzw6QGi6vnjAyw_2imEd7WWdvzl63hHGczbzT0LSQ_RXP_OzPwidv03lswXiR6-AiY7r8lXq_YMrrufSjlPkc6TGr_ad768A3GNGsJK5nLI2eGlAj_kq80Xod0l267IA3zlNxNwAd_socpcoeuvlr_dAQ6NdVYC6TzzD_e62RNXmr0_Dx0Wm7hu2dms2j0_djpo2rbxoTm5kiu_r6exkd-WA6VMN6Yiq8082cm_2r_r2rWsNBwEsR0MDrSWmTps26_TG7_pdPzprr6pLxznm__WG7wNm769dcGj2Rw0A3m-2c7MS_pX6vZxDe_W2ibndiY0oRGwk_ZXN3YzzrG7SsCOLd0L2rrni7GTAQvB6PNvlinOr7vtq7NtNvNHSnzpm_NQN3wazRm3zf0pqjmsdBwX5B666BPTm2Y9iQG_znNN5xLtlj6lSB0GAfGdzohM5x6CrRG0oT6tz606LTNzAjuEljNeDBhODR-n2PNgAP0wlyw0ddpfmeNxsj06S8euleNao6_Qoj7I6PYXDrnDmrwBiivt66Y8lfmti7zvz_mYl3zzmvzfldmHDRwrGi65l_rM2RYs2TGu2R7XSrEnkiukod0NSdpWic0nA8mlDr6yzczIoRzoA3hHoRzIrnmRGjmXS_eCoRZMm7NHrRGL2BCMleGIl7eYL6NMzZYoqihGoBZnrQNtiiu2dx0sirWzGOwuk_pp2QlWqcunGcu9SPLxq8LMGvvh92b*"

# Decode with salt=8 (outer encoding)
alphabet_8 = derive_custom_base64_alphabet(salt=8)
decoded_8 = custom_base64_decode(setCertBlob, alphabet_8)

try:
    text_result = decoded_8.decode("utf-8", errors="strict").strip()
    # The decoded result is already formatted base64 - just add headers
    print("-----BEGIN CERTIFICATE-----")
    print(text_result)
    print("-----END CERTIFICATE-----")
except Exception as e:
    # Error to stderr so it doesn't interfere with piping
    print(f"Error: Not a text certificate - got binary data", file=sys.stderr)
    sys.exit(1)
