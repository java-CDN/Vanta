# Vanta

Local-only, multi-profile privacy browser for Windows 10/11. Source of truth: `../plan/master/Vanta-Master-Plan-v2.pdf`.

## Layout
- `crates/vanta-types` shared types (EngineVersion, ProfileId, exit codes 86/87/88)
- `crates/vanta-vault` Argon2id + XChaCha20-Poly1305, per-profile keys, recovery key, auto-lock (F09, F18)
- `crates/vanta-store` SQLite + FTS5 profile DB and search language (F01, F10, F16)
- `crates/vanta-fingerprint` real-device personas, UA/UA-CH from engine version, rules C001–C031, signed config (F02, F12, F20)

## Develop
```
export PATH=$HOME/.cargo/bin:$PATH CARGO_TARGET_DIR=/tmp/vanta-target
bash scripts/check.sh
```
