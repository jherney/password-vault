# Test data

## keepassxc-YubiKeyProtectedPasswords.kdbx

Copied unchanged from KeePassXC 2.8.0, `tests/data/YubiKeyProtectedPasswords.kdbx`
(https://github.com/keepassxreboot/keepassxc/blob/2.8.0/tests/data/YubiKeyProtectedPasswords.kdbx).
KeePassXC is licensed under the GNU GPL version 2 or 3; pwvault is GPL-3.0-or-later.

- Password: `a`
- YubiKey HMAC-SHA1 secret (any slot): `1ce30fd78d20dcfa40b50c18779afb0f02288db7`
  (from KeePassXC's `tests/TestCli.cpp`, which also gives the known answer for the challenge
  `CLITest`: `a23b9400be479a30a9eb509b85565b6b3025b48e`)
- Entries: `entry1`, `entry2`

`tests/test_yubikey.py` opens it with an emulated YubiKey to check that pwvault derives the key
exactly as KeePassXC does. This file is test data only; it is not part of the published package.
