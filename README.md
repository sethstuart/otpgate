# OtpGate

Password-free login for Paper servers in **offline mode**: every player proves who they are with a 6-digit
code from an authenticator app (Google Authenticator, Aegis, 2FAS, 1Password, ...), and nothing else.

Offline-mode servers (and Bedrock players through Geyser) can't rely on Mojang to check that a name belongs
to the person using it, so anyone can join as anyone. AuthMe-style plugins fix that with passwords, and can
only add 2FA *on top* of a password. OtpGate is code-only: no password to forget, reuse or leak. Enrolment
needs a one-time setup code that only the server console can issue, so a stolen name is useless twice over:
no setup code to enrol, no phone to log in.

## What players see

- **First time:** an admin runs `otp issue <name>` in the console and gives the player the setup code. The
  player joins and types `/otp setup <setupcode>`. OtpGate shows the key as text **and as a QR code on a map in
  their hand**; they scan it, then `/otp confirm <code>` to finish (and log in). They have 10 minutes.
- **Every login:** `/otp <code>`. Rejoining from the same IP within 10 minutes needs no code.
- **Until they log in**, a player can't move, chat, run other commands, interact, or take damage. They're kicked
  after 120 seconds or 5 wrong codes. Each 30-second code works once (no replay).

## Commands

| Who | Command | What it does |
|---|---|---|
| player | `/otp <code>` | log in |
| player | `/otp setup <setupcode>` | start enrolment: shows the key + QR map |
| player | `/otp confirm <code>` | finish enrolment |
| console | `otp issue <name>` | one-time setup code (wipes any existing key) |
| console | `otp setkey <name> <base32>` | set a key directly (bots, migrations) |
| console | `otp remove <name>` / `otp list` | remove a player / list enrolled players |

Data lives in `plugins/OtpGate/players.yml`. Keys use `/` as the path separator, because Bedrock (Geyser /
Floodgate) names start with `.`.

**Bots:** a bot can log in with `/otp <code>` by computing standard TOTP (RFC 6238, SHA-1, 6 digits, 30 s)
from the key you gave it with `otp setkey`.

## Requirements

- Paper 1.21.11+ / 26.x (built against Java 21 and the Paper API; `api-version: 1.21.11`).
- Works with Geyser + Floodgate. Floodgate players are treated like everyone else.

## Building

There's no build tool yet:

1. Put the Paper API jars on the classpath (for example, a server's `/minecraft/libraries` copied to `libs/`),
   plus [zxing core 3.5.3](https://repo1.maven.org/maven2/com/google/zxing/core/3.5.3/) for the QR map
   (sha1 `ca1349214a356cd7958651b2d5a0e1f3811a9c4b`).
2. `javac --release 21 -cp "<libs jars>;core-3.5.3.jar" -d out src/dev/rei/otpgate/OtpGate.java`
3. Copy `src/plugin.yml` into `out/`, add the `com/google/zxing/**` classes from zxing core, and zip `out/`
   as `OtpGate-1.1.0.jar`.

The TOTP code is checked against the RFC 6238 test vectors.

## Known limitations

- The issuer label shown in authenticator apps is hardcoded (`ISSUER` in `OtpGate.java`). It should be a config
  option.
- No Gradle or Maven build yet.
- Sessions are remembered per IP for 10 minutes, a trade-off for convenience on a small, known player list.

## Who made this

OtpGate was built on 2026-10-08 for a small friends' server after it was griefed by a bot that joined under
other players' names. It's maintained by **Rei**, an AI agent who also plays on that server (as ReiBot, who
logs in with her own key). It was written with Seth Stuart, who owns the server.

## License

MIT. See [LICENSE](LICENSE). The QR code generation bundles [ZXing](https://github.com/zxing/zxing) core,
which is Apache-2.0.
