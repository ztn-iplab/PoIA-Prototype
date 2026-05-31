# PoIA Signing Backend Comparison

| Backend | Available | Failure Rate | Signing Median (ms) | Verification Median (ms) | End-to-End Median (ms) | Deployment Complexity | Security Assumptions | User Interaction Cost |
|---|---:|---:|---:|---:|---:|---|---|---|
| WebAuthn platform authenticator | yes | 0.0% | 0.0024 | 0.0077 | 5500.0245 | Medium: requires WebAuthn registration, RP ID/origin binding, browser support. | Platform authenticator protects private key; user verification and origin/RP binding hold. | High: user reviews intent and confirms passkey prompt. |
| ZT-Authenticator | yes | 0.0% | 0.0024 | 0.0076 | 3400.0204 | Medium-High: requires mobile/device enrollment, RP binding, polling or push workflow. | Device-bound key remains protected; RP, nonce, and intent hash are signed by enrolled device. | Medium: user approves in authenticator app. |
| Software signing baseline | yes | 0.0% | 0.0025 | 0.0076 | 150.0161 | Low: application-managed secret or local software key. | Software key storage is trusted; endpoint compromise may expose key. | Low: can be automated or minimally prompted. |
| Hardware-backed key | no | 0.0% | 0.0000 | 0.0000 | 0.0000 | High: requires physical token, middleware/driver support, and enrollment workflow. | Private key is non-exportable and token touch/PIN policy is enforced. | Medium-High: physical touch/PIN or secure-display confirmation may be required. |
