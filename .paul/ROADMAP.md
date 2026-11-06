---
description: "pwvault — milestone and phase structure"
type: Roadmap
about: "pwvault"
---

# Roadmap: pwvault

## Overview

Close the gaps that keep pwvault from being a daily-driver password manager, without leaving Python, pykeepass or the KDBX format: merge vault copies edited on two devices, unlock with a YubiKey, check passwords against known breaches offline, and fill logins in the browser.

## Current Milestone

**v1.4 Daily-driver gaps** (v1.4.0)
Status: 🚧 In progress
Phases: 3 of 4 complete (75%)

Constraints for every phase:
- Stays on pykeepass; no custom crypto, no new vault format. A vault written by any phase must still open in KeePassXC.
- Every write goes through `Vault._write()` (lock, conflict check, backup, atomic write).
- Each phase ends with a `/cso` pass on its changes before it is marked complete.

## Phases

| Phase | Name | Plans | Status | Completed |
|-------|------|-------|--------|-----------|
| 6 | Vault merge | 2/2 | ✅ Complete | 2026-11-05 |
| 7 | YubiKey unlock | 2/2 | ✅ Complete | 2026-11-05 |
| 8 | Offline breach check | 3/3 | ✅ Complete | 2026-11-05 |
| 9 | Browser autofill | TBD | Not started | - |

## Phase Details

### Phase 6: Vault merge ✅

**Goal:** `pwvault merge OTHER.kdbx` combines two copies of a vault the way KeePassXC does, so editing on two devices never loses a change
**Depends on:** Nothing (first phase)
**Research:** Likely (KeePassXC merge rules: per-entry UUID match, LastModificationTime, history, DeletedObjects)

**Scope:**
- Match entries and groups by UUID; the newer version wins, the older one goes into the entry's history
- Honor deletions recorded in DeletedObjects; moves between groups follow the newer LocationChanged
- Open the other vault with its own credentials; save once through `Vault._write()` (backed up)
- Report what was added, updated and deleted; `--dry-run` shows it without saving
- Interop test: a vault merged by pwvault and the same merge in keepassxc-cli give the same entries
- Builds on, or replaces, `merge_records` (pwvault.py) used by CSV import

**Plans:**
- [x] 06-01: merge engine (UUID match, history, moves, DeletedObjects, attachments, icons), `pwvault merge` CLI, keepassxc-cli interop test
- [x] 06-02: GUI Database > Merge another copy… dialog (preview, Save, Discard); `open_other_copy()` shared with the CLI

### Phase 7: YubiKey unlock ✅

**Goal:** Unlock a vault with password + YubiKey HMAC-SHA1 challenge-response, in the same way KeePassXC does, so one vault works with the same key in both apps
**Depends on:** Phase 6
**Research:** Likely (KeePassXC challenge-response: challenge = master seed, response mixed into the composite key; yubikey-manager or ykchalresp as the driver)

**Scope:**
- CLI and GUI: unlock, init and re-key with a YubiKey slot
- Clear errors when no key is plugged in or the slot is not configured
- Optional dependency only; the vault opens without it when no YubiKey is configured
- Verified against a vault created by KeePassXC with the same key

**Plans:**
- [x] 07-01 (AC-5 hardware check deferred): YubiKey through all load/save paths, KeePassXC-compatible challenge-response (proven offline against KeePassXC's own YubiKey test vault), optional `yubikey-manager` driver, CLI `--yubikey`; real-key checkpoint
- [x] 07-02: GUI (unlock/create screens with remembered slot, Change master key, Merge), touch prompt; PR #6 reviewed by CodeRabbit

**Open item:** first use with a physical YubiKey and `keepassxc-cli -y` (07-01 AC-5)

### Phase 8: Offline breach check ✅

**Goal:** `pwvault check` lists entries whose passwords appear in known breaches, without sending any password or hash prefix over the network during the check
**Depends on:** Nothing (independent of Phases 6–7)
**Research:** Likely (HIBP Pwned Passwords download size and format, sorted SHA-1 file, binary search)

**Scope:**
- A download/update command for the hash list, kept outside the vault folder
- Lookup by binary search over the sorted file; no full load into memory
- Also flag reused and weak passwords from what is already in the vault
- GUI: a report dialog that opens the flagged entries

**Plans:**
- [x] 08-01 (AC-5 real download deferred): compact HIBP store (download with resume, import, lookup), `pwvault check` (breached, reused, weak), `pwvault breach update|import|status`
- [x] 08-02: GUI Database > Check passwords… report; double-click selects the entry in the main window
- [x] 08-03: breach-store integrity (index SHA-256, per-range CRC32), note and import free-space leftovers, phase `/cso` on 08-01 and 08-02 (no supported findings; download size capped)

**Open item:** first real `pwvault breach update` against HIBP (08-01 AC-5)

### Phase 9: Browser autofill

**Goal:** Fill and save logins in Firefox and Chromium from the unlocked pwvault
**Depends on:** Phases 6–8 (largest and riskiest phase, done last)
**Research:** Likely (WebExtension native messaging, KeePassXC-Browser protocol reuse vs. own, origin matching, phishing resistance)

**Scope:**
- Native messaging host started by the browser; talks only to an unlocked vault, asks before each fill
- WebExtension that fills on exact origin match and offers to save new logins
- Threat model and `/cso` review before anything ships

**Plans:** TBD (defined during /paul:plan)

---

## Completed Milestones

### v1.3 Hardening, TOTP, Backups & Release (complete 2026-11-05)
Phases 1–5: safe saves and backups, TOTP codes, GUI polish, security review, packaging and PyPI release (`pwvault-manager` 1.3.0, tag v1.3.0 at ce9009e). Archive: milestones/1.3.0-ROADMAP.md

---
*Roadmap created: 2026-10-30*
*Last updated: 2026-11-05 — Phase 8 complete*
