"""Tests for merging two copies of a vault. Run: python3 -m unittest discover -s tests"""

import base64
import io
import shutil
import subprocess
import sys
import unittest
import uuid
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from lxml import etree

from test_pwvault import PW, Base, pwvault
from pwvault import Vault, merge_vaults

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def at(minutes: int) -> datetime:
    return T0 + timedelta(minutes=minutes)


def stamp(vault, item, minutes, tag="LastModificationTime") -> None:
    item._element.find(f"Times/{tag}").text = vault.kp._encode_time(at(minutes))


def get(vault, entry_uuid):
    return next((e for e in vault.kp.entries if e.uuid == entry_uuid), None)


def snapshot(kp) -> dict:
    """What a person sees: every live entry by UUID, with its fields, group path and trash state."""
    bin_ = kp.recyclebin_group
    out = {}
    for e in kp.entries:
        in_bin = False
        g = e.group
        while g is not None:
            in_bin = in_bin or (bin_ is not None and g.uuid == bin_.uuid)
            g = g.parentgroup
        out[e.uuid] = (e.title or "", e.username or "", e.password or "", e.url or "", e.notes or "",
                       "/".join(p or "" for p in (e.group.path or [])), in_bin)
    return out


class MergeBase(Base):
    """Vault A with a few entries, all stamped at T0, and B: a copy of A's file."""

    def setUp(self):
        super().setUp()
        self.path_b = self.tmp / "copy.kdbx"
        a = Vault.create(self.path, PW)
        self.work = a.add_group(a.root, "Work")
        self.ids = {}
        for name in ("X", "Y", "Z", "M", "T", "D", "K"):
            e = a.add_entry(self.work if name in "MTDK" else a.root, name, "me", f"{name}-0")
            self.ids[name] = e.uuid
        for item in [self.work, *a.kp.entries]:
            stamp(a, item, 0)
            stamp(a, item, 0, "LocationChanged")
        a.save()
        shutil.copyfile(self.path, self.path_b)

    def a(self):
        return Vault.open(self.path, PW)

    def b(self):
        return Vault.open(self.path_b, PW)

    def edit(self, vault, name, minutes, **fields):
        e = get(vault, self.ids[name])
        vault.update_entry(e, fields)
        stamp(vault, e, minutes)
        return e


class MergeEntryTests(MergeBase):
    def test_edits_on_both_sides_survive(self):
        a, b = self.a(), self.b()
        self.edit(a, "X", 5, password="X-a")
        self.edit(b, "Y", 5, password="Y-b")
        self.edit(a, "Z", 5, password="Z-a")
        self.edit(b, "Z", 10, password="Z-b")
        b.save()
        b_bytes = self.path_b.read_bytes()

        report = merge_vaults(a, b.kp)
        a.save()

        a = self.a()
        self.assertEqual(get(a, self.ids["X"]).password, "X-a")
        self.assertEqual(get(a, self.ids["Y"]).password, "Y-b")
        z = get(a, self.ids["Z"])
        self.assertEqual(z.password, "Z-b")
        self.assertEqual([h.password for h in z.history], ["Z-0", "Z-a"])  # nothing lost
        self.assertEqual(self.path_b.read_bytes(), b_bytes)  # the other file is never written
        self.assertEqual(sorted(t for _, t in report.updated), ["Y", "Z"])
        self.assertEqual(report.added, [])

    def test_older_other_side_still_lands_in_history(self):
        a, b = self.a(), self.b()
        self.edit(b, "Z", 5, password="Z-b")
        self.edit(a, "Z", 10, password="Z-a")
        merge_vaults(a, b.kp)
        z = get(a, self.ids["Z"])
        self.assertEqual(z.password, "Z-a")
        self.assertEqual([h.password for h in z.history], ["Z-0", "Z-b"])

    def test_history_is_capped(self):
        a, b = self.a(), self.b()
        for i in range(1, 9):
            self.edit(a, "Z", i, password=f"a{i}")
            self.edit(b, "Z", 100 + i, password=f"b{i}")
        merge_vaults(a, b.kp)
        z = get(a, self.ids["Z"])
        self.assertEqual(z.password, "b8")
        self.assertEqual(len(z.history), pwvault.HISTORY_MAX)
        self.assertEqual(z.history[-1].password, "b7")  # the newest versions are the ones kept

    def test_merge_is_idempotent_and_symmetric(self):
        a, b = self.a(), self.b()
        self.edit(a, "X", 5, password="X-a")
        self.edit(b, "Y", 5, password="Y-b")
        self.edit(a, "Z", 5, password="Z-a")
        self.edit(b, "Z", 10, password="Z-b")
        b.delete_entry(get(b, self.ids["T"]))
        a.save()
        b.save()

        ab, ba = self.a(), self.b()
        merge_vaults(ab, self.b().kp)
        merge_vaults(ba, self.a().kp)
        self.assertEqual(snapshot(ab.kp), snapshot(ba.kp))

        ab.save()
        again = merge_vaults(self.a(), self.b().kp)
        self.assertFalse(again.changed, again)


class MergeStructureTests(MergeBase):
    def add_icon(self, vault, data: bytes) -> str:
        meta = vault.kp.tree.getroot().find("Meta")
        icons = meta.find("CustomIcons")
        if icons is None:
            icons = etree.SubElement(meta, "CustomIcons")
        icon_id = base64.b64encode(uuid.uuid4().bytes).decode()
        icon = etree.SubElement(icons, "Icon")
        etree.SubElement(icon, "UUID").text = icon_id
        etree.SubElement(icon, "Data").text = base64.b64encode(data).decode()
        return icon_id

    def test_new_groups_entries_attachments_and_icons(self):
        a, b = self.a(), self.b()
        a.add_attachment(get(a, self.ids["X"]), "a.txt", b"only in A")  # A's pool differs from B's
        a.save()
        a = self.a()
        outer = b.add_group(b.root, "New")
        inner = b.add_group(outer, "Nested")
        e = b.add_entry(inner, "Fresh", "me", "f-1")
        b.update_entry(e, {"password": "f-2"}, add_attachments=[("v1.bin", b"\x00first\xff")])
        b.update_entry(e, {"password": "f-3"}, remove_attachments=list(e.attachments),
                       add_attachments=[("v2.bin", b"second")])
        icon_id = self.add_icon(b, b"\x89PNG fake icon")
        etree.SubElement(e._element, "CustomIconUUID").text = icon_id
        b.save()

        report = merge_vaults(a, self.b().kp)
        a.save()
        a = self.a()

        fresh = next(x for x in a.kp.entries if x.title == "Fresh")
        self.assertEqual(fresh.uuid, e.uuid)
        self.assertEqual(fresh.group.path, ["New", "Nested"])
        self.assertEqual(fresh.group.uuid, inner.uuid)
        self.assertEqual([(x.filename, x.data) for x in fresh.attachments], [("v2.bin", b"second")])
        # pykeepass's .attachments doesn't read history versions, so follow the reference by hand.
        self.assertIn(("v1.bin", b"\x00first\xff"),
                      [(b.findtext("Key"), a.kp.binaries[int(b.find("Value").get("Ref"))])
                       for h in fresh.history for b in h._element.findall("Binary")])
        self.assertEqual(get(a, self.ids["X"]).attachments[0].data, b"only in A")
        icons = a.kp.tree.getroot().findall("Meta/CustomIcons/Icon")
        self.assertIn(icon_id, [i.findtext("UUID") for i in icons])
        self.assertEqual(report.added, [("Root", "New/"), ("Root/New", "Nested/"),
                                        ("Root/New/Nested", "Fresh")])

    def test_group_rename_and_move_follow_the_newer_side(self):
        a, b = self.a(), self.b()
        target = b.add_group(b.root, "Archive")
        group = next(g for g in b.kp.groups if g.uuid == self.work.uuid)
        group.name = "Job"
        b.kp.move_group(group, target)
        b._moved(group)
        group.touch(modify=True)
        b.save()

        merge_vaults(a, self.b().kp)
        moved = next(g for g in a.kp.groups if g.uuid == self.work.uuid)
        self.assertEqual(moved.name, "Job")
        self.assertEqual(moved.path, ["Archive", "Job"])


class MergeDeletionTests(MergeBase):
    def test_moves_trash_and_permanent_deletes_carry_over(self):
        a, b = self.a(), self.b()
        archive = b.add_group(b.root, "Archive")
        b.update_entry(get(b, self.ids["M"]), {}, group=archive)
        b.delete_entry(get(b, self.ids["T"]))  # to the recycle bin
        d = get(b, self.ids["D"])
        b.delete_entry(d)
        b.delete_entry(d)  # and out of it: permanent
        k = get(b, self.ids["K"])
        b.delete_entry(k)
        b.delete_entry(k)
        b.save()
        # A edits K after B deleted it, so A's K stays.
        self.edit(a, "K", 0, password="K-a")
        stamp(a, get(a, self.ids["K"]), 60 * 24 * 365 * 5)

        report = merge_vaults(a, self.b().kp)
        a.save()
        a = self.a()
        self.assertEqual(get(a, self.ids["M"]).group.path, ["Archive"])
        self.assertTrue(a.in_recycle_bin(get(a, self.ids["T"])))
        self.assertIsNone(get(a, self.ids["D"]))
        self.assertEqual(get(a, self.ids["K"]).password, "K-a")
        self.assertEqual([t for _, t in report.deleted], ["D"])
        self.assertIn("M", [t for _, t in report.moved])

    def test_deleted_group_with_new_content_on_this_side_is_kept(self):
        a, b = self.a(), self.b()
        work = next(g for g in b.kp.groups if g.uuid == self.work.uuid)
        b.delete_group(work)
        b.delete_group(next(g for g in b.kp.groups if g.uuid == self.work.uuid))  # permanent
        b.save()
        new = a.add_entry(next(g for g in a.kp.groups if g.uuid == self.work.uuid), "Late", "me", "l")

        merge_vaults(a, self.b().kp)
        self.assertIsNotNone(get(a, new.uuid))
        self.assertEqual(get(a, new.uuid).group.uuid, self.work.uuid)
        for name in "MTDK":  # B's deletion of the group's old entries does apply
            self.assertIsNone(get(a, self.ids[name]), name)

    def test_permanent_deletes_are_recorded(self):
        v = self.a()

        def deleted():
            return {base64.b64decode(o.findtext("UUID"))
                    for o in v.kp.tree.getroot().findall("Root/DeletedObjects/DeletedObject")}

        x = get(v, self.ids["X"])
        v.delete_entry(x)
        self.assertEqual(deleted(), set())  # trashing is a move, not a deletion
        v.delete_entry(x)
        self.assertEqual(deleted(), {self.ids["X"].bytes})

        work = next(g for g in v.kp.groups if g.uuid == self.work.uuid)
        v.delete_group(work)
        v.delete_group(next(g for g in v.kp.groups if g.uuid == self.work.uuid))
        expected = {self.ids["X"].bytes, self.work.uuid.bytes} | {self.ids[n].bytes for n in "MTDK"}
        self.assertEqual(deleted(), expected)

        v.delete_entry(get(v, self.ids["Y"]))
        v.empty_recycle_bin()
        self.assertIn(self.ids["Y"].bytes, deleted())
        v.save()
        self.assertIn(self.ids["Y"].bytes, {base64.b64decode(o.findtext("UUID")) for o in
                      self.a().kp.tree.getroot().findall("Root/DeletedObjects/DeletedObject")})

    def test_moves_stamp_location_changed(self):
        v = self.a()
        x = get(v, self.ids["X"])
        before = v.kp._decode_time(x._element.findtext("Times/LocationChanged"))
        v.update_entry(x, {}, group=next(g for g in v.kp.groups if g.uuid == self.work.uuid))
        self.assertGreater(v.kp._decode_time(x._element.findtext("Times/LocationChanged")), before)


@unittest.skipUnless(shutil.which("keepassxc-cli"), "keepassxc-cli is not installed")
class KeePassXCInteropTests(MergeBase):
    """The same two copies merged by pwvault and by keepassxc-cli give the same entries."""

    def keepassxc(self, *argv):
        return subprocess.run(["keepassxc-cli", *argv], input=PW + "\n", capture_output=True,
                              text=True, timeout=120, check=True)

    def test_same_result_as_keepassxc(self):
        a, b = self.a(), self.b()
        self.edit(a, "X", 5, password="X-a")
        self.edit(b, "Y", 5, password="Y-b", notes="changed in B")
        self.edit(a, "Z", 5, password="Z-a")
        self.edit(b, "Z", 10, password="Z-b", title="Z renamed")
        archive = b.add_group(b.root, "Archive")
        b.update_entry(get(b, self.ids["M"]), {}, group=archive)
        b.delete_entry(get(b, self.ids["T"]))
        d = get(b, self.ids["D"])
        b.delete_entry(d)
        b.delete_entry(d)
        b.add_entry(b.get_group("Archive/Old", create=True), "From B", "bee", "b-pw", "https://b.example")
        a.add_entry(a.root, "From A", "ay", "a-pw")
        a.save()
        b.save()

        mine, theirs = self.tmp / "mine.kdbx", self.tmp / "theirs.kdbx"
        shutil.copyfile(self.path, mine)
        shutil.copyfile(self.path, theirs)
        v = Vault.open(mine, PW)
        merge_vaults(v, self.b().kp)
        v.save()
        self.keepassxc("merge", "-s", "-q", str(theirs), str(self.path_b))

        ours = snapshot(Vault.open(mine, PW).kp)
        kpxc = snapshot(Vault.open(theirs, PW).kp)
        # KeePassXC's default merge mode keeps permanently deleted entries; pwvault applies the
        # deletion (decided in Phase 6). Everything else must match.
        self.assertIn(self.ids["D"], kpxc)
        self.assertNotIn(self.ids["D"], ours)
        del kpxc[self.ids["D"]]
        # A had no recycle bin yet. KeePassXC copies B's over as a plain group (a TODO in its
        # Merger.cpp); pwvault makes it A's recycle bin, so T shows as trashed. Same group path.
        t = self.ids["T"]
        self.assertEqual((ours[t][5], ours[t][6], kpxc[t][6]), ("Recycle Bin", True, False))
        kpxc[t] = kpxc[t][:6] + (True,)
        self.assertEqual(ours, kpxc)
        listing = self.keepassxc("ls", "-R", "-q", str(mine)).stdout  # KeePassXC opens our result
        self.assertIn("From B", listing)
        self.assertIn("Z renamed", listing)

    def test_changes_made_in_keepassxc_merge_in(self):
        self.keepassxc("edit", "-q", "-u", "edited-in-kpxc", str(self.path_b), "Y")
        self.keepassxc("rm", "-q", str(self.path_b), "Work/D")
        self.keepassxc("rm", "-q", str(self.path_b), "Recycle Bin/D")  # permanent, KeePassXC records it
        a = self.a()
        report = merge_vaults(a, self.b().kp)
        a.save()
        a = self.a()
        self.assertEqual(get(a, self.ids["Y"]).username, "edited-in-kpxc")
        self.assertIsNone(get(a, self.ids["D"]))
        self.assertIn("D", [t for _, t in report.deleted])


OTHER_PW = "the other copy has its own long password"


class MergeCliTests(MergeBase):
    def run_cli(self, *argv, prompts=()):
        """Run `pwvault merge`; getpass answers PW for this vault, then each of prompts."""
        answers = iter((PW, *prompts))
        out = io.StringIO()
        with patch.object(sys, "argv", ["pwvault", "--vault", str(self.path), "merge", *argv]), \
                patch("getpass.getpass", side_effect=lambda *a, **k: next(answers)), \
                redirect_stdout(out):
            try:
                pwvault.main()
                code = 0
            except SystemExit as e:
                code = e.code
        return code, out.getvalue()

    def backups(self):
        return pwvault.list_backups(self.path)

    def change_b(self):
        b = self.b()
        self.edit(b, "Y", 5, password="Y-b")
        b.save()

    def test_merge_saves_once_with_a_backup(self):
        self.change_b()
        before = len(self.backups())
        code, out = self.run_cli(str(self.path_b), "--same-credentials")
        self.assertEqual(code, 0, out)
        self.assertIn("~ Root/Y", out)
        self.assertIn("0 added, 1 updated, 0 moved, 0 deleted.", out)
        self.assertEqual(get(self.a(), self.ids["Y"]).password, "Y-b")
        self.assertEqual(len(self.backups()), before + 1)

    def test_dry_run_saves_nothing(self):
        self.change_b()
        vault_bytes = self.path.read_bytes()
        code, out = self.run_cli(str(self.path_b), "--same-credentials", "--dry-run")
        self.assertEqual(code, 0, out)
        self.assertIn("~ Root/Y", out)
        self.assertIn("Dry run: nothing saved.", out)
        self.assertEqual(self.path.read_bytes(), vault_bytes)

    def test_nothing_to_merge(self):
        before = len(self.backups())
        code, out = self.run_cli(str(self.path_b), "--same-credentials")
        self.assertEqual(code, 0, out)
        self.assertIn("Already up to date.", out)
        self.assertEqual(len(self.backups()), before)

    def test_other_copy_with_its_own_password_and_key_file(self):
        keyfile = self.tmp / "other.keyx"
        pwvault.generate_keyfile(keyfile)
        b = self.b()
        self.edit(b, "Y", 5, password="Y-b")
        b.rekey(OTHER_PW, keyfile)
        b.save()
        code, out = self.run_cli(str(self.path_b), "--other-keyfile", str(keyfile), prompts=(OTHER_PW,))
        self.assertEqual(code, 0, out)
        self.assertEqual(get(self.a(), self.ids["Y"]).password, "Y-b")

    def test_wrong_password_for_the_other_copy(self):
        self.change_b()
        vault_bytes = self.path.read_bytes()
        code, _ = self.run_cli(str(self.path_b), prompts=("not the password",))
        self.assertRegex(str(code), r"copy\.kdbx: wrong master password")
        self.assertEqual(self.path.read_bytes(), vault_bytes)

    def test_refuses_to_merge_the_vault_with_itself(self):
        link = self.tmp / "link.kdbx"
        link.symlink_to(self.path)
        for target in (self.path, link):
            code, _ = self.run_cli(str(target), "--same-credentials")
            self.assertRegex(str(code), r"this vault itself")

    def test_missing_other_file(self):
        code, _ = self.run_cli(str(self.tmp / "nope.kdbx"))
        self.assertRegex(str(code), r"no file at")


if __name__ == "__main__":
    unittest.main()
