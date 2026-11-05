---
phase: 07-yubikey-unlock
plan: 01
subsystem: crypto/keys
tags: [yubikey, hmac-sha1, challenge-response, kdbx4, argon2, keepassxc, cli]

requires:
  - phase: 06-vault-merge
    provides: open_other_copy() (now takes the YubiKey too)
provides:
  - KeePassXC-compatible YubiKey challenge-response in the master key (KDBX 4 + Argon2)
  - YubiKeySlot, challenge_response() driver (optional yubikey-manager), keyfile_key(), read_kdf_params()
  - CLI --yubikey SLOT[:SERIAL], passwd --new-yubikey/--no-yubikey, merge --other-yubikey
affects: [07-02 GUI, any future unlock path]

tech-stack:
  added: ["yubikey-manager>=5.5 (optional extra [yubikey])"]
  patterns:
    - "pwvault derives the transformed key itself and hands it to pykeepass (transformed_key=); saving with it keeps the KDF salt"
    - "Hardware is replaced in tests by an emulator of the device behavior (strip padding, HMAC-SHA1), never by a production switch"

key-files:
  created: [tests/test_yubikey.py, tests/data/keepassxc-YubiKeyProtectedPasswords.kdbx, tests/data/README.md]
  modified: [pwvault.py, pwvault_gui.py, pyproject.toml, README.md, CHANGELOG.md]

key-decisions:
  - "Optional yubikey= parameter on existing Vault/load functions instead of a MasterKey type"
  - "--yubikey is a global option like --keyfile"
  - "A YubiKey counts as a strong factor: password may be short or blank with it"
  - "AC-5 (real hardware) deferred: no key available"

duration: ~2h
started: 2026-11-05T18:45:00-04:00
completed: 2026-11-05T20:30:00-04:00
description: "YubiKey HMAC-SHA1 challenge-response as part of the master key, byte-compatible with KeePassXC 2.8 (proven offline against KeePassXC's own YubiKey test vault), with CLI options and an optional yubikey-manager driver"
type: Summary
about: "pwvault"
---

# Phase 7 Plan 01: YubiKey challenge-response (core + CLI) Summary

**A YubiKey HMAC-SHA1 slot can now be part of a vault's master key, derived exactly as KeePassXC 2.8 does for KDBX 4: pwvault opens KeePassXC's own YubiKey-protected test vault with an emulated key. The CLI takes `--yubikey SLOT[:SERIAL]` everywhere. Not yet run against a physical key.**

## Performance

| Metric | Value |
|--------|-------|
| Duration | ~2h |
| Tasks | 2 of 2 auto; checkpoint deferred (no hardware) |
| Tests | 218 OK (195 + 23 in tests/test_yubikey.py) |

## Acceptance Criteria Results

| Criterion | Status | Notes |
|-----------|--------|-------|
| AC-1: KeePassXC compatibility (no hardware) | Pass | Known answer `CLITest` matches; KeePassXC's vault opens with password `a` + emulated key → entry1, entry2; fails without the key or with another secret |
| AC-2: Create, save, re-key | Pass | Create/save/reopen; routine saves don't re-challenge; add/change/remove via re-key, fresh salt each time, old-key backups purged; key file + YubiKey without a password |
| AC-3: Every unlock path | Pass | All commands go through `unlock()`; restore and merge (`--same-credentials` includes the YubiKey) tested; `--other-yubikey` |
| AC-4: Errors, optional dependency | Pass | Missing extra, no key, several keys, serial not found, slot not set up, touch timeout, driver error, KDBX 3 / AES-KDF; non-YubiKey vaults never call the driver |
| AC-5: Real hardware | **Deferred** | No YubiKey available (user, 2026-11-05) |

## Accomplishments

- KeePassXC's scheme read from source (`CompositeKey::rawKey/transform/challenge`, `YubiKeyInterfacePCSC`) and proven before coding against KeePassXC's test vault and published secret
- Driver calls checked against yubikey-manager 5.9.2 source: `list_all_devices() -> [(device, info)]`, `YubiOtpSession.calculate_hmac_sha1(slot, challenge, event, on_keepalive)` (pads only below 64 bytes, so KeePassXC's block passes unchanged), `get_config_state().is_configured(slot)`
- `read_kdf_params()` now serves both the KDF cost check and the YubiKey salt; `keyfile_key()` proven equal to pykeepass's derivation for every key-file format

## Files Created/Modified

| File | Change | Purpose |
|------|--------|---------|
| `pwvault.py` | Modified | YubiKey section (YubiKeySlot, challenge block, driver, keyfile_key, derivation), `load_kdbx`/`Vault` yubikey parameter, save with fresh salt, CLI options |
| `pwvault_gui.py` | Modified | Existing open/reload/re-key/merge calls carry `vault.yubikey` (GUI can't start a YubiKey unlock yet) |
| `pyproject.toml` | Modified | Extra `yubikey = ["yubikey-manager>=5.5"]` |
| `tests/test_yubikey.py` | Created | 23 tests: KeePassXC compatibility, key files, vault life cycle, driver (stand-in modules), CLI |
| `tests/data/…YubiKeyProtectedPasswords.kdbx`, `tests/data/README.md` | Created | KeePassXC 2.8.0 test vault with source, licence, password, secret |
| `README.md`, `CHANGELOG.md` | Modified | YubiKey section (spare-key warning, pyscard build note), command table, Unreleased |

## Deviations from Plan

| Type | Count | Impact |
|------|-------|--------|
| Design simplification | 2 | Less churn, same behavior |
| Spec correction | 1 | Exact KeePassXC padding semantics |
| Deferred | 1 | AC-5 hardware check |

- **No `MasterKey` type:** `yubikey=` added to `Vault.create/open/rekey`, `load_kdbx`, `open_other_copy`; the Vault keeps `.yubikey`. GUI and ~190 existing tests unchanged.
- **`--yubikey` global** (like `--keyfile`): `pwvault --yubikey 2 init`, not `init --yubikey 2`.
- **Padding:** the plan said "HMAC over the unpadded challenge". Precisely: KeePassXC sends `challenge + bytes([64-n])*(64-n)` and a variable-length slot strips every trailing byte equal to the last one (so also challenge bytes equal to the pad value). pwvault sends the same block; the emulator models the strip.
- **GUI touched** (plan said 07-02): only to pass `vault.yubikey` through existing calls, so Change master key can't silently drop a YubiKey.

### Deferred Items

- AC-5: first use with a physical YubiKey and keepassxc-cli `-y` both ways
- `pip install` of the extra needs `pcsc-lite-devel` (pyscard builds from source); README notes it

## Issues Encountered

| Issue | Resolution |
|-------|------------|
| First proof failed the known answer (HMAC over padded block) | Device strips padding; HMAC over the stripped block matches |
| `python3 -I` hid user site-packages for the proof | Used `-P` (cwd not on sys.path; no .py files in the download dir) |
| yubikey-manager wouldn't install (pyscard build) | Installed with `--no-deps` in a scratch venv to inspect the API only |

## Next Phase Readiness

**Ready:** 07-02 can call `Vault.open/create/rekey(..., yubikey=)` and `challenge_response` (prompt text via stderr today; GUI needs its own "Touch your YubiKey" status).
**Concerns:** Driver unverified on hardware; GUI testing will also be emulator-only.
**Blockers:** None

---
*Phase: 07-yubikey-unlock, Plan: 01*
*Completed: 2026-11-05*
