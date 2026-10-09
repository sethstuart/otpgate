# OtpGate

Authenticator-app login for node07 (Paper 26.3, offline mode), no password. Written 2026-10-08 after the
FishNet attack, replacing AuthMe (which can only add 2FA on top of a password; Seth wanted code-only).

- Player: `/otp <code>` to log in; first time `/otp setup <setupcode>` (shows the key for the app) then
  `/otp confirm <code>`. Same IP within 10 minutes = no code. Locked players can't move, chat, use other
  commands, interact or take damage; kicked after 120 s or 5 wrong codes. A 30 s code step works once.
- Console: `otp issue <name>` (one-time setup code; wipes the old key), `otp setkey <name> <base32>`,
  `otp remove <name>`, `otp list`. Data: `plugins/OtpGate/players.yml` (path separator `/`: Bedrock names
  start with `.`).
- ReiBot computes her code from `auth.json` `otpSecret` (body.cjs).

Build (no build tool): copy the server's `/minecraft/libraries` jars to `libs/`, then
`javac --release 21 -cp "<all libs jars>" -d out src/dev/rei/otpgate/OtpGate.java`, copy `src/plugin.yml`
into `out/`, and zip `out/` as `OtpGate-1.0.0.jar`. Tested against the RFC 6238 vectors.
