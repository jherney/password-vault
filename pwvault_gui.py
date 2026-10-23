#!/usr/bin/env python3
"""pwvault GUI — Tkinter front end for pwvault's KeePass (.kdbx) vault.

Uses the same vault file and code as the `pwvault.py` CLI.
"""

import os
import sys
import tkinter as tk
from pathlib import Path
from time import monotonic
from tkinter import filedialog, messagebox, simpledialog, ttk

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pwvault  # noqa: E402
from pwvault import Vault, VaultError  # noqa: E402

AUTO_LOCK_SECONDS = 5 * 60
# An open edit dialog can keep an idle vault unlocked this long, then the vault locks anyway.
DIALOG_HOLD_SECONDS = 10 * 60
CLIP_SECONDS = pwvault.CLIPBOARD_CLEAR_SECONDS

BG, PANEL, FG, MUTED, ACCENT, DANGER = "#1e1f26", "#2a2c36", "#e6e6eb", "#9a9cab", "#6c8cff", "#e5636b"
STRENGTH_COLORS = {"weak": DANGER, "fair": "#e0b050", "strong": "#6cc28a", "very strong": "#6cc28a"}


def apply_style(root: tk.Tk) -> None:
    root.configure(bg=BG)
    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(".", background=BG, foreground=FG, fieldbackground=PANEL, bordercolor=PANEL,
                font=("Sans", 10))
    s.configure("TFrame", background=BG)
    s.configure("Panel.TFrame", background=PANEL)
    s.configure("TLabel", background=BG, foreground=FG)
    s.configure("Panel.TLabel", background=PANEL)
    s.configure("Muted.TLabel", foreground=MUTED)
    s.configure("PanelMuted.TLabel", background=PANEL, foreground=MUTED)
    s.configure("Title.TLabel", font=("Sans", 18, "bold"))
    s.configure("Error.TLabel", foreground=DANGER)
    s.configure("TButton", background=PANEL, foreground=FG, padding=(10, 5), borderwidth=0)
    s.map("TButton", background=[("active", "#3a3d4a")])
    s.configure("Small.TButton", padding=(6, 2))
    s.configure("Accent.TButton", background=ACCENT, foreground="#ffffff")
    s.map("Accent.TButton", background=[("active", "#5a7af0")])
    s.configure("Danger.TButton", foreground=DANGER)
    s.configure("TEntry", foreground=FG, insertcolor=FG, padding=5)
    s.configure("TCombobox", foreground=FG, arrowcolor=FG, padding=4)
    s.map("TCombobox", fieldbackground=[("readonly", PANEL)], foreground=[("readonly", FG)])
    s.configure("TCheckbutton", background=BG, foreground=FG)
    s.map("TCheckbutton", background=[("active", BG)])
    s.configure("TSpinbox", foreground=FG, arrowcolor=FG, padding=4)
    s.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=FG, rowheight=26,
                borderwidth=0)
    s.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", "#ffffff")])
    s.configure("Treeview.Heading", background=BG, foreground=MUTED, borderwidth=0,
                font=("Sans", 9, "bold"))
    s.map("Treeview.Heading", background=[("active", BG)])
    root.option_add("*TCombobox*Listbox.background", PANEL)
    root.option_add("*TCombobox*Listbox.foreground", FG)


class PasswordField(ttk.Frame):
    """Entry with a show/hide toggle."""

    def __init__(self, master, textvariable=None, width=30, **kw):
        super().__init__(master, **kw)
        self.var = textvariable or tk.StringVar()
        self.entry = ttk.Entry(self, textvariable=self.var, show="•", width=width)
        self.entry.pack(side="left", fill="x", expand=True)
        self.btn = ttk.Button(self, text="Show", width=5, command=self.toggle)
        self.btn.pack(side="left", padx=(4, 0))

    def toggle(self):
        hidden = self.entry.cget("show") != ""
        self.entry.configure(show="" if hidden else "•")
        self.btn.configure(text="Hide" if hidden else "Show")


class KeyFileField(ttk.Frame):
    """Optional key-file path with Browse (and, when creating, New) buttons."""

    def __init__(self, master, app, allow_new=False, **kw):
        super().__init__(master, **kw)
        self.app = app
        self.var = tk.StringVar()
        ttk.Entry(self, textvariable=self.var, width=24).pack(side="left", fill="x", expand=True)
        ttk.Button(self, text="Browse…", command=self.browse).pack(side="left", padx=(4, 0))
        if allow_new:
            ttk.Button(self, text="New…", command=self.new).pack(side="left", padx=(4, 0))

    def browse(self):
        path = filedialog.askopenfilename(parent=self.winfo_toplevel(), title="Select key file")
        if path:
            self.var.set(path)

    def new(self):
        path = filedialog.asksaveasfilename(parent=self.winfo_toplevel(), title="Create key file",
                                            initialfile="pwvault.keyx")
        if not path:
            return
        try:
            pwvault.generate_keyfile(Path(path))
        except (VaultError, OSError) as e:
            return messagebox.showerror("Key file", str(e), parent=self.winfo_toplevel())
        self.var.set(path)
        messagebox.showinfo("Key file created", f"{path}\n\nBack this file up somewhere safe. "
                            "Without it the vault can't be opened.", parent=self.winfo_toplevel())

    def get(self):
        return self.var.get().strip() or None


def strength_label(master, var, style_bg=BG):
    """Label that tracks the strength of the password in var."""
    lbl = tk.Label(master, text="", bg=style_bg, fg=MUTED, font=("Sans", 8))

    def update(*_):
        pw = var.get()
        if not pw:
            return lbl.configure(text="")
        bits, label = pwvault.strength(pw)
        lbl.configure(text=f"{label} · ~{bits} bits", fg=STRENGTH_COLORS[label])
    var.trace_add("write", update)
    update()
    return lbl


class Dialog(tk.Toplevel):
    def __init__(self, app, title):
        super().__init__(app.root)
        self.app = app
        self.title(title)
        self.configure(bg=BG)
        self.transient(app.root)
        self.resizable(False, False)
        self.body = ttk.Frame(self, padding=16)
        self.body.pack(fill="both", expand=True)
        self.bind("<Escape>", lambda e: self.destroy())

    def show(self):
        self.update_idletasks()
        r = self.app.root
        x = r.winfo_rootx() + (r.winfo_width() - self.winfo_width()) // 2
        y = r.winfo_rooty() + (r.winfo_height() - self.winfo_height()) // 3
        self.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        self.wait_visibility()
        self.grab_set()


class EntryDialog(Dialog):
    def __init__(self, app, entry=None, group=None):
        super().__init__(app, "Edit entry" if entry else "Add entry")
        self.entry = entry
        v = app.vault
        self.vars = {k: tk.StringVar(value=(getattr(entry, k) or "") if entry else "")
                     for k in ("title", "url", "username", "password")}
        b = self.body
        for row, (key, label) in enumerate([("title", "Title"), ("username", "Username")]):
            ttk.Label(b, text=label).grid(row=row, column=0, sticky="w", pady=4, padx=(0, 10))
            ttk.Entry(b, textvariable=self.vars[key], width=44).grid(row=row, column=1, columnspan=2, sticky="ew")
        ttk.Label(b, text="Password").grid(row=2, column=0, sticky="w", pady=4)
        self.pw = PasswordField(b, self.vars["password"], width=32)
        self.pw.grid(row=2, column=1, sticky="ew")
        ttk.Button(b, text="Generate", command=self.generate).grid(row=2, column=2, padx=(4, 0))
        strength_label(b, self.vars["password"]).grid(row=3, column=1, sticky="w")
        ttk.Label(b, text="URL").grid(row=4, column=0, sticky="w", pady=4)
        ttk.Entry(b, textvariable=self.vars["url"], width=44).grid(row=4, column=1, columnspan=2, sticky="ew")

        ttk.Label(b, text="Group").grid(row=5, column=0, sticky="w", pady=4)
        self.groups = v.groups()
        self.group_names = [v.group_path(g) for g in self.groups]
        current = entry.group if entry and not v.in_recycle_bin(entry) else (group or v.root)
        self.group = tk.StringVar(value=v.group_path(current))
        ttk.Combobox(b, textvariable=self.group, values=self.group_names, state="readonly").grid(
            row=5, column=1, columnspan=2, sticky="ew")

        ttk.Label(b, text="Expires").grid(row=6, column=0, sticky="w", pady=4)
        exp = ttk.Frame(b)
        exp.grid(row=6, column=1, columnspan=2, sticky="w")
        has_expiry = bool(entry and entry.expires)
        self.expires = tk.BooleanVar(value=has_expiry)
        self.expiry = tk.StringVar(value=entry.expiry_time.astimezone().strftime("%Y-%m-%d") if has_expiry else "")
        ttk.Checkbutton(exp, variable=self.expires, command=self.toggle_expiry).pack(side="left")
        self.expiry_entry = ttk.Entry(exp, textvariable=self.expiry, width=12)
        self.expiry_entry.pack(side="left")
        ttk.Label(exp, text="  YYYY-MM-DD", style="Muted.TLabel").pack(side="left")
        self.toggle_expiry()

        ttk.Label(b, text="Notes").grid(row=7, column=0, sticky="nw", pady=4)
        self.notes = tk.Text(b, width=44, height=4, bg=PANEL, fg=FG, insertbackground=FG,
                             relief="flat", wrap="word", font=("Sans", 10))
        self.notes.insert("1.0", (entry.notes or "") if entry else "")
        self.notes.grid(row=7, column=1, columnspan=2, sticky="ew", pady=4)

        # Attachment changes are staged here and applied on Save.
        self.attachments = list(entry.attachments) if entry else []
        self.to_add, self.to_remove = [], []
        ttk.Label(b, text="Attachments").grid(row=8, column=0, sticky="nw", pady=4)
        att = ttk.Frame(b)
        att.grid(row=8, column=1, columnspan=2, sticky="ew", pady=4)
        self.att_list = tk.Listbox(att, height=3, bg=PANEL, fg=FG, relief="flat", highlightthickness=0,
                                   selectbackground=ACCENT)
        self.att_list.pack(side="left", fill="x", expand=True)
        abtns = ttk.Frame(att)
        abtns.pack(side="left", padx=(4, 0))
        ttk.Button(abtns, text="Add…", style="Small.TButton", command=self.add_attachment).pack(fill="x")
        ttk.Button(abtns, text="Remove", style="Small.TButton", command=self.remove_attachment).pack(fill="x", pady=2)
        self.refresh_attachments()

        self.err = ttk.Label(b, text="", style="Error.TLabel")
        self.err.grid(row=9, column=0, columnspan=3, sticky="w")
        btns = ttk.Frame(b)
        btns.grid(row=10, column=0, columnspan=3, sticky="e", pady=(8, 0))
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="left", padx=4)
        ttk.Button(btns, text="Save", style="Accent.TButton", command=self.save).pack(side="left")
        self.bind("<Return>", lambda ev: self.save() if ev.widget is not self.notes else None)
        self.show()

    def toggle_expiry(self):
        self.expiry_entry.configure(state="normal" if self.expires.get() else "disabled")

    def generate(self):
        self.vars["password"].set(pwvault.generate_password(24))
        if self.pw.entry.cget("show"):
            self.pw.toggle()

    def refresh_attachments(self):
        self.att_list.delete(0, "end")
        for a in self.attachments:
            self.att_list.insert("end", a.filename)
        for name, data in self.to_add:
            self.att_list.insert("end", f"{name}  (new, {len(data):,} bytes)")

    def add_attachment(self):
        path = filedialog.askopenfilename(parent=self, title="Attach file")
        if not path:
            return
        try:
            self.to_add.append((Path(path).name, Path(path).read_bytes()))
        except OSError as e:
            return messagebox.showerror("Attach file", str(e), parent=self)
        self.refresh_attachments()

    def remove_attachment(self):
        sel = self.att_list.curselection()
        if not sel:
            return
        i = sel[0]
        if i < len(self.attachments):
            self.to_remove.append(self.attachments.pop(i))
        else:
            self.to_add.pop(i - len(self.attachments))
        self.refresh_attachments()

    def save(self):
        v = self.app.vault
        if v is None:
            return self.destroy()
        f = {k: var.get().strip() for k, var in self.vars.items()}
        f["password"] = self.vars["password"].get()  # don't strip passwords
        f["notes"] = self.notes.get("1.0", "end").strip()
        if not (f["title"] or f["url"]):
            return self.err.configure(text="Give the entry a title or URL.")
        if not f["password"]:
            return self.err.configure(text="Enter or generate a password.")
        f["title"] = f["title"] or f["url"]
        try:
            expiry = pwvault.expiry_from_date(self.expiry.get()) if self.expires.get() else None
        except VaultError as e:
            return self.err.configure(text=str(e).capitalize() + ".")
        if self.expires.get() and expiry is None:
            return self.err.configure(text="Enter an expiry date, or untick Expires.")
        group = self.groups[self.group_names.index(self.group.get())]
        if self.entry:
            v.update_entry(self.entry, f, group, expiry, self.to_add, self.to_remove)
            entry = self.entry
        else:
            entry = v.add_entry(group, f["title"], f["username"], f["password"], f["url"], f["notes"], expiry)
            for name, data in self.to_add:
                v.add_attachment(entry, name, data)
        if self.app.save():
            self.app.show_group(group, select=entry)
        self.destroy()


class HistoryDialog(Dialog):
    def __init__(self, app, entry):
        super().__init__(app, f"History — {entry.title}")
        self.entry = entry
        self.versions = list(reversed(entry.history))  # newest first
        b = self.body
        if not self.versions:
            ttk.Label(b, text="No earlier versions yet. A version is saved each time you edit this entry.",
                      style="Muted.TLabel", wraplength=360).pack()
            ttk.Button(b, text="Close", command=self.destroy).pack(anchor="e", pady=(12, 0))
            return self.show()
        self.tree = ttk.Treeview(b, columns=("when", "title", "username", "password"), show="headings",
                                 height=min(10, len(self.versions)), selectmode="browse")
        for col, label, w in [("when", "Saved", 130), ("title", "Title", 150),
                              ("username", "Username", 150), ("password", "Password", 150)]:
            self.tree.heading(col, text=label)
            self.tree.column(col, width=w, anchor="w")
        for i, h in enumerate(self.versions):
            self.tree.insert("", "end", iid=str(i), values=(pwvault.fmt_time(h.mtime), h.title or "",
                                                           h.username or "", "•" * 8))
        self.tree.pack(fill="both", expand=True)
        self.tree.selection_set("0")
        btns = ttk.Frame(b)
        btns.pack(fill="x", pady=(10, 0))
        ttk.Button(btns, text="Show password", command=self.reveal).pack(side="left")
        ttk.Button(btns, text="Close", command=self.destroy).pack(side="right")
        ttk.Button(btns, text="Restore this version", style="Accent.TButton",
                   command=self.restore).pack(side="right", padx=4)
        self.show()

    def selected(self):
        sel = self.tree.selection()
        return self.versions[int(sel[0])] if sel else None

    def reveal(self):
        h = self.selected()
        if h:
            self.tree.set(self.tree.selection()[0], "password", h.password or "")

    def restore(self):
        h = self.selected()
        if h is None or self.app.vault is None:
            return
        self.app.vault.restore_history(self.entry, h)
        if self.app.save():
            self.app.refresh()
            self.app.status(f"Restored the version from {pwvault.fmt_time(h.mtime)}.")
        self.destroy()


class GeneratorDialog(Dialog):
    def __init__(self, app):
        super().__init__(app, "Password generator")
        b = self.body
        self.length = tk.IntVar(value=24)
        self.opts = {k: tk.BooleanVar(value=k != "exclude_lookalikes")
                     for k in ("upper", "lower", "digits", "symbols", "exclude_lookalikes")}
        self.out = tk.StringVar()
        ttk.Entry(b, textvariable=self.out, width=46, font=("Monospace", 11)).grid(
            row=0, column=0, columnspan=4, sticky="ew")
        strength_label(b, self.out).grid(row=1, column=0, columnspan=4, sticky="w", pady=(2, 10))
        ttk.Label(b, text="Length").grid(row=2, column=0, sticky="w")
        ttk.Spinbox(b, from_=pwvault.MIN_GENERATED_LEN, to=128, textvariable=self.length, width=5,
                    command=self.regen).grid(row=2, column=1, sticky="w", padx=6)
        for i, (key, label) in enumerate([("upper", "A–Z"), ("lower", "a–z"), ("digits", "0–9"),
                                          ("symbols", "Symbols"), ("exclude_lookalikes", "No look-alikes (l 1 O 0)")]):
            ttk.Checkbutton(b, text=label, variable=self.opts[key], command=self.regen).grid(
                row=3 + i // 2, column=(i % 2) * 2, columnspan=2, sticky="w", pady=2)
        self.err = ttk.Label(b, text="", style="Error.TLabel")
        self.err.grid(row=6, column=0, columnspan=4, sticky="w")
        btns = ttk.Frame(b)
        btns.grid(row=7, column=0, columnspan=4, sticky="e", pady=(8, 0))
        ttk.Button(btns, text="Regenerate", command=self.regen).pack(side="left", padx=4)
        ttk.Button(btns, text="Copy", style="Accent.TButton",
                   command=lambda: self.app.copy(self.out.get(), "Password")).pack(side="left")
        self.regen()
        self.show()

    def regen(self):
        try:
            n = max(pwvault.MIN_GENERATED_LEN, min(128, int(self.length.get())))
        except (tk.TclError, ValueError):
            n = 24
        try:
            self.out.set(pwvault.generate_password(n, **{k: v.get() for k, v in self.opts.items()}))
            self.err.configure(text="")
        except VaultError as e:
            self.err.configure(text=str(e).capitalize() + ".")


class ChangeMasterDialog(Dialog):
    def __init__(self, app):
        super().__init__(app, "Change master key")
        b = self.body
        self.cur, self.new, self.confirm = tk.StringVar(), tk.StringVar(), tk.StringVar()
        for row, (label, var) in enumerate([("Current password", self.cur), ("New password", self.new),
                                            ("Confirm new", self.confirm)]):
            ttk.Label(b, text=label).grid(row=row, column=0, sticky="w", pady=4, padx=(0, 10))
            PasswordField(b, var).grid(row=row, column=1, sticky="ew")
        strength_label(b, self.new).grid(row=3, column=1, sticky="w")
        ttk.Label(b, text="New key file").grid(row=4, column=0, sticky="w", pady=4)
        self.keyfile = KeyFileField(b, app, allow_new=True)
        self.keyfile.grid(row=4, column=1, sticky="ew")
        if app.vault.kp.keyfile:
            self.keyfile.var.set(app.vault.kp.keyfile)
        ttk.Label(b, text="Leave the key file empty to unlock with the password alone.",
                  style="Muted.TLabel").grid(row=5, column=0, columnspan=2, sticky="w")
        self.err = ttk.Label(b, text="", style="Error.TLabel")
        self.err.grid(row=6, column=0, columnspan=2, sticky="w")
        btns = ttk.Frame(b)
        btns.grid(row=7, column=0, columnspan=2, sticky="e", pady=(10, 0))
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="left", padx=4)
        ttk.Button(btns, text="Change", style="Accent.TButton", command=self.apply).pack(side="left")
        self.bind("<Return>", lambda e: self.apply())
        self.show()

    def apply(self):
        if self.new.get() != self.confirm.get():
            return self.err.configure(text="New passwords don't match.")
        try:
            pwvault.check_master_key(self.new.get(), self.keyfile.get())
        except VaultError as e:
            return self.err.configure(text=str(e).capitalize() + ".")
        with self.app.busy():
            try:
                Vault.open(self.app.vault.path, self.cur.get(), self.app.vault.kp.keyfile)
            except VaultError:
                return self.err.configure(text="Current password is wrong.")
            self.app.vault.rekey(self.new.get(), self.keyfile.get())
            if not self.app.save():
                return
        self.app.status("Master key changed.")
        self.destroy()


class App:
    def __init__(self, vault_path: Path):
        self.path = vault_path
        self.vault = None
        self.clip_job = None
        self.clip_text = None
        self.lock_job = None
        self.hold_since = None  # when an open dialog first deferred the idle lock
        self.current_group = None
        self.items = {}  # treeview iid -> pykeepass Entry / Group
        self.root = tk.Tk(className="pwvault")
        self.root.title("pwvault")
        self.root.geometry("1180x640")
        self.root.minsize(860, 480)
        apply_style(self.root)
        self.root.bind_all("<Any-KeyPress>", self.touch, add="+")
        self.root.bind_all("<Any-ButtonPress>", self.touch, add="+")
        self.root.protocol("WM_DELETE_WINDOW", self.quit)
        self.frame = None
        self.show_unlock()

    # ---------------------------------------------------------- utilities

    class _Busy:
        def __init__(self, root): self.root = root
        def __enter__(self):
            self.root.configure(cursor="watch"); self.root.update()
        def __exit__(self, *a):
            self.root.configure(cursor="")

    def busy(self):
        return self._Busy(self.root)

    def swap(self, frame):
        if self.frame:
            self.frame.destroy()
        self.frame = frame
        frame.pack(fill="both", expand=True)

    def status(self, msg):
        if hasattr(self, "status_lbl") and self.status_lbl.winfo_exists():
            self.status_lbl.configure(text=msg)

    def copy(self, text, what):
        if not text:
            return
        # Prefer wl-copy/xclip (survives on Wayland, auto-clears); fall back to Tk's clipboard.
        if not pwvault.copy_to_clipboard(text):
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.clip_text = text
            if self.clip_job:
                self.root.after_cancel(self.clip_job)
            self.clip_job = self.root.after(CLIP_SECONDS * 1000, self.clear_clipboard)
        self.status(f"{what} copied — clipboard clears in {CLIP_SECONDS}s.")

    def clear_clipboard(self):
        self.clip_job = None
        text, self.clip_text = self.clip_text, None
        try:
            # Leave the clipboard alone if the user has copied something else since.
            if self.root.clipboard_get() == text:
                self.root.clipboard_clear()
                self.root.clipboard_append("")
        except tk.TclError:
            pass

    def touch(self, _event=None):
        if self.vault is None:
            return
        self.hold_since = None
        self.arm_idle_timer(AUTO_LOCK_SECONDS)

    def arm_idle_timer(self, seconds):
        if self.lock_job:
            self.root.after_cancel(self.lock_job)
        self.lock_job = self.root.after(int(seconds * 1000), self.auto_lock)

    def auto_lock(self):
        """Idle timer. An open dialog holds edits in progress, so the lock waits for it to close, but
        only for DIALOG_HOLD_SECONDS; after that the vault locks and the dialog's edits are discarded."""
        self.lock_job = None
        dialogs_open = any(isinstance(w, tk.Toplevel) for w in self.root.winfo_children())
        if dialogs_open:
            now = monotonic()
            if self.hold_since is None:
                self.hold_since = now
            remaining = DIALOG_HOLD_SECONDS - (now - self.hold_since)
            if remaining > 0:
                return self.arm_idle_timer(remaining)
        else:
            self.hold_since = None
        self.lock("Locked after inactivity." + (" An open edit was discarded." if dialogs_open else ""))

    def lock(self, msg=""):
        if self.lock_job:
            self.root.after_cancel(self.lock_job)
            self.lock_job = None
        self.vault = None
        self.items = {}
        for w in self.root.winfo_children():
            if isinstance(w, tk.Toplevel):
                w.destroy()
        self.show_unlock(msg)

    def quit(self):
        if self.clip_job:
            self.clear_clipboard()
        self.root.destroy()

    def save(self) -> bool:
        """Write the vault. On failure, report it and lock so unsaved in-memory changes are dropped
        and the next unlock reloads what is actually on disk."""
        try:
            with self.busy():
                self.vault.save()
            return True
        except (VaultError, OSError) as err:
            messagebox.showerror("Save failed", str(err).capitalize() + ".", parent=self.root)
            self.lock("Not saved — vault reloaded from disk.")
            return False

    # ---------------------------------------------------------- unlock / create / migrate screen

    def show_unlock(self, msg=""):
        self.root.title(f"pwvault — {self.path.name}")
        migrating = (not self.path.exists() and self.path == pwvault.DEFAULT_VAULT
                     and pwvault.LEGACY_VAULT.exists())
        creating = not self.path.exists() and not migrating
        f = ttk.Frame(self.root)
        self.swap(f)
        box = ttk.Frame(f, padding=30)
        box.place(relx=0.5, rely=0.42, anchor="center")
        ttk.Label(box, text="🔐 pwvault", style="Title.TLabel").pack(pady=(0, 4))
        subtitle = ("Convert your vault to KeePass format — enter its master password" if migrating
                    else "Create a new vault" if creating else "Enter your master key")
        ttk.Label(box, text=subtitle, style="Muted.TLabel").pack(pady=(0, 16))
        pw, confirm = tk.StringVar(), tk.StringVar()
        ttk.Label(box, text="Master password", style="Muted.TLabel").pack(anchor="w")
        field = PasswordField(box, pw, width=32)
        field.pack(fill="x", pady=4)
        if creating:
            ttk.Label(box, text="Confirm", style="Muted.TLabel").pack(anchor="w", pady=(8, 0))
            PasswordField(box, confirm, width=32).pack(fill="x", pady=4)
            strength_label(box, pw).pack(anchor="w")
        if not migrating:
            ttk.Label(box, text="Key file (optional)", style="Muted.TLabel").pack(anchor="w", pady=(8, 0))
            keyfile = KeyFileField(box, self, allow_new=creating)
            keyfile.pack(fill="x", pady=4)
        if creating:
            ttk.Label(box, text=f"Use a password of at least {pwvault.MIN_MASTER_LEN} characters, a key file, "
                                "or both. Neither can be recovered if lost.",
                      style="Muted.TLabel", wraplength=340).pack(pady=(6, 0))
        if migrating:
            ttk.Label(box, text=f"Your entries will be copied into {self.path.name} (a KeePass file). "
                                f"The old {pwvault.LEGACY_VAULT.name} is kept untouched.",
                      style="Muted.TLabel", wraplength=340).pack(pady=(6, 0))
        err = ttk.Label(box, text=msg, style="Muted.TLabel" if msg else "Error.TLabel", wraplength=340)
        err.pack(pady=8)
        ttk.Label(box, text=str(self.path), style="Muted.TLabel", font=("Sans", 8)).pack(side="bottom")

        def submit(_e=None):
            p = pw.get()
            kf = None if migrating else keyfile.get()
            if creating and p != confirm.get():
                return err.configure(text="Passwords don't match.", style="Error.TLabel")
            with self.busy():
                try:
                    if migrating:
                        vault = pwvault.migrate_legacy(pwvault.LEGACY_VAULT, self.path, p)
                    elif creating:
                        vault = Vault.create(self.path, p, kf)
                        vault.save()
                    else:
                        vault = Vault.open(self.path, p, kf)
                except (VaultError, OSError) as e:
                    pw.set("")
                    return err.configure(text=str(e).capitalize() + ".", style="Error.TLabel")
            self.vault = vault
            self.touch()
            self.show_main()
            if migrating:
                self.status(f"Converted {len(vault.kp.entries)} entries to KeePass format. "
                            f"You can delete {pwvault.LEGACY_VAULT} once you've checked them.")

        label = "Convert vault" if migrating else "Create vault" if creating else "Unlock"
        ttk.Button(box, text=label, style="Accent.TButton", command=submit).pack(fill="x", pady=(0, 8))
        if not creating:
            links = ttk.Frame(box)
            links.pack()
            ttk.Button(links, text="Open other…", style="Small.TButton", command=self.open_other).pack(side="left")
            ttk.Button(links, text="New vault…", style="Small.TButton", command=self.new_vault).pack(side="left", padx=4)
        self.root.bind("<Return>", submit)
        field.entry.focus_set()

    def open_other(self):
        path = filedialog.askopenfilename(parent=self.root, title="Open KeePass database",
                                          initialdir=str(self.path.parent),
                                          filetypes=[("KeePass databases", "*.kdbx"), ("All files", "*")])
        if path:
            self.path = Path(path)
            self.lock()

    def new_vault(self):
        path = filedialog.asksaveasfilename(parent=self.root, title="Create new vault",
                                            initialdir=str(self.path.parent), defaultextension=".kdbx",
                                            filetypes=[("KeePass databases", "*.kdbx")])
        if not path:
            return
        if Path(path).exists():
            return messagebox.showerror("New vault", f"{path} already exists. Use Open instead.", parent=self.root)
        self.path = Path(path)
        self.lock()

    # ---------------------------------------------------------- main screen

    def show_main(self):
        self.root.unbind("<Return>")
        f = ttk.Frame(self.root, padding=10)
        self.swap(f)

        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=(0, 8))
        self.search = tk.StringVar()
        self.search.trace_add("write", lambda *a: self.refresh())
        se = ttk.Entry(bar, textvariable=self.search, width=30)
        se.pack(side="left")
        se.focus_set()
        ttk.Label(bar, text="  search all groups", style="Muted.TLabel").pack(side="left")
        for text, cmd, style in [("🔒 Lock", self.lock, "TButton"),
                                 ("Database ▾", self.database_menu, "TButton"),
                                 ("Generator", lambda: GeneratorDialog(self), "TButton"),
                                 ("+ Add", self.add_entry, "Accent.TButton")]:
            b = ttk.Button(bar, text=text, command=cmd, style=style)
            b.pack(side="right", padx=2)
            if text.startswith("Database"):
                self.db_btn = b

        body = ttk.Frame(f)
        body.pack(fill="both", expand=True)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        # Groups
        left = ttk.Frame(body)
        left.grid(row=0, column=0, sticky="ns", padx=(0, 10))
        self.gtree = ttk.Treeview(left, show="tree", selectmode="browse")
        self.gtree.column("#0", width=180)
        self.gtree.pack(fill="both", expand=True)
        gbtns = ttk.Frame(left)
        gbtns.pack(fill="x", pady=(6, 0))
        ttk.Button(gbtns, text="+ Group", style="Small.TButton", command=self.add_group).pack(side="left")
        ttk.Button(gbtns, text="Rename", style="Small.TButton", command=self.rename_group).pack(side="left", padx=4)
        ttk.Button(gbtns, text="Delete", style="Small.TButton", command=self.delete_group).pack(side="left")
        self.gtree.bind("<<TreeviewSelect>>", lambda e: self.on_group_select())

        # Entries
        mid = ttk.Frame(body)
        mid.grid(row=0, column=1, sticky="nsew")
        cols = [("title", "Title", 140), ("username", "Username", 120), ("url", "URL", 130),
                ("modified", "Modified", 110)]
        self.tree = ttk.Treeview(mid, columns=[c[0] for c in cols], show="headings", selectmode="browse")
        for col, label, w in cols:
            self.tree.heading(col, text=label, command=lambda c=col: self.sort_by(c))
            self.tree.column(col, width=w, anchor="w")
        self.tree.tag_configure("expired", foreground=DANGER)
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")

        # Details
        self.detail = ttk.Frame(body, style="Panel.TFrame", padding=14, width=330)
        self.detail.grid(row=0, column=2, sticky="ns", padx=(10, 0))
        self.detail.pack_propagate(False)

        self.status_lbl = ttk.Label(f, text="", style="Muted.TLabel")
        self.status_lbl.pack(fill="x", pady=(6, 0))

        self.tree.bind("<<TreeviewSelect>>", lambda e: self.show_detail())
        self.tree.bind("<Double-1>", lambda e: self.edit_selected())
        self.tree.bind("<Delete>", lambda e: self.delete_selected())
        self.root.bind_all("<Control-c>", lambda e: self.shortcut_copy("password", e))
        self.root.bind_all("<Control-b>", lambda e: self.shortcut_copy("username", e))
        self.root.bind("<Control-n>", lambda e: self.add_entry())
        self.root.bind("<Control-f>", lambda e: se.focus_set())
        self.root.bind("<Control-l>", lambda e: self.lock())

        self.sort_col = "title"
        self.current_group = self.vault.root
        self.refresh_groups()
        self.status(f"{len(self.vault.kp.entries)} entries · double-click a field to copy it · "
                    f"Ctrl+C copy password · Ctrl+B copy username · auto-locks after {AUTO_LOCK_SECONDS // 60} min idle")

    # ---------------------------------------------------------- groups

    def refresh_groups(self):
        v = self.vault
        self.gtree.delete(*self.gtree.get_children())
        self.items = {k: x for k, x in self.items.items() if not k.startswith("g:")}
        bin_ = v.recycle_bin

        def add(group, parent):
            iid = f"g:{group.uuid}"
            is_bin = bin_ is not None and group.uuid == bin_.uuid
            icon = "🗑" if is_bin else "📁"
            self.gtree.insert(parent, "end", iid=iid, text=f"{icon} {group.name}", open=True)
            self.items[iid] = group
            subs = sorted(group.subgroups, key=lambda s: (bin_ is not None and s.uuid == bin_.uuid,
                                                          (s.name or "").lower()))
            for sub in subs:
                add(sub, iid)
        add(v.root, "")
        target = f"g:{self.current_group.uuid}" if self.current_group else f"g:{v.root.uuid}"
        if not self.gtree.exists(target):
            target = f"g:{v.root.uuid}"
        self.gtree.selection_set(target)
        self.gtree.see(target)
        self.on_group_select()

    def selected_group(self):
        sel = self.gtree.selection()
        return self.items.get(sel[0]) if sel else self.vault.root

    def on_group_select(self):
        self.current_group = self.selected_group()
        if self.search.get():
            self.search.set("")  # triggers refresh
        else:
            self.refresh()

    def show_group(self, group, select=None):
        self.current_group = group
        self.search.set("")
        self.refresh_groups()
        if select is not None and self.tree.exists(f"e:{select.uuid}"):
            self.tree.selection_set(f"e:{select.uuid}")
            self.tree.see(f"e:{select.uuid}")

    def add_group(self):
        parent = self.selected_group()
        if self.vault.in_recycle_bin(parent):
            return messagebox.showinfo("New group", "Pick a group outside the recycle bin.", parent=self.root)
        name = simpledialog.askstring("New group", f"Name of the new group inside '{parent.name}':",
                                      parent=self.root)
        if not name or self.vault is None:
            return
        try:
            group = self.vault.add_group(parent, name)
        except VaultError as e:
            return messagebox.showerror("New group", str(e).capitalize() + ".", parent=self.root)
        if self.save():
            self.show_group(group)

    def rename_group(self):
        group = self.selected_group()
        name = simpledialog.askstring("Rename group", "New name:", initialvalue=group.name, parent=self.root)
        if not name or self.vault is None:
            return
        try:
            self.vault.rename_group(group, name)
        except VaultError as e:
            return messagebox.showerror("Rename group", str(e).capitalize() + ".", parent=self.root)
        if self.save():
            self.refresh_groups()

    def delete_group(self):
        v, group = self.vault, self.selected_group()
        permanent = v.in_recycle_bin(group)
        question = (f"Permanently delete '{group.name}' and everything in it?\nThis cannot be undone." if permanent
                    else f"Move '{group.name}' and everything in it to the recycle bin?")
        if not messagebox.askyesno("Delete group", question,
                                   icon="warning", parent=self.root) or self.vault is None:
            return
        try:
            v.delete_group(group)
        except VaultError as e:
            return messagebox.showerror("Delete group", str(e).capitalize() + ".", parent=self.root)
        if self.save():
            self.show_group(v.root)

    # ---------------------------------------------------------- entries

    def sort_by(self, col):
        self.sort_col = col
        self.refresh()

    def refresh(self):
        if self.vault is None:
            return
        v = self.vault
        q = self.search.get().strip()
        entries = v.entries(self.current_group, q)
        sel = self.selected()
        self.tree.delete(*self.tree.get_children())
        self.items = {k: x for k, x in self.items.items() if not k.startswith("e:")}
        key = {"title": lambda e: (e.title or "").lower(), "username": lambda e: (e.username or "").lower(),
               "url": lambda e: (e.url or "").lower(), "modified": lambda e: e.mtime}[self.sort_col]
        for e in sorted(entries, key=key, reverse=self.sort_col == "modified"):
            iid = f"e:{e.uuid}"
            self.items[iid] = e
            title = e.title or ""
            if e.expired:
                title += "  (expired)"
            self.tree.insert("", "end", iid=iid, tags=("expired",) if e.expired else (),
                             values=(title, e.username or "", e.url or "", pwvault.fmt_time(e.mtime)))
        if sel and self.tree.exists(f"e:{sel.uuid}"):
            self.tree.selection_set(f"e:{sel.uuid}")
        elif self.tree.get_children():
            self.tree.selection_set(self.tree.get_children()[0])
        self.show_detail()

    def selected(self):
        if not hasattr(self, "tree") or not self.tree.winfo_exists():
            return None
        sel = self.tree.selection()
        return self.items.get(sel[0]) if sel else None

    def show_detail(self):
        for w in self.detail.winfo_children():
            w.destroy()
        e = self.selected()
        if not e:
            ttk.Label(self.detail, text="No entry selected", style="PanelMuted.TLabel").pack(anchor="w")
            return
        v = self.vault
        in_bin = v.in_recycle_bin(e)
        d = self.detail
        ttk.Label(d, text=e.title or "", style="Panel.TLabel", font=("Sans", 14, "bold"),
                  wraplength=290).pack(anchor="w")
        ttk.Label(d, text=("🗑 in recycle bin" if in_bin else "📁 " + v.group_path(e.group)),
                  style="PanelMuted.TLabel").pack(anchor="w", pady=(0, 10))

        def row(label, value, copy_key=None, secret=False):
            ttk.Label(d, text=label, style="PanelMuted.TLabel", font=("Sans", 8, "bold")).pack(anchor="w")
            line = ttk.Frame(d, style="Panel.TFrame")
            line.pack(fill="x", pady=(0, 8))
            # Buttons are packed first so a long value can never push them out of view.
            if copy_key and value:
                ttk.Button(line, text="Copy", width=5, command=lambda: self.copy_field(copy_key)).pack(side="right")
            lbl = ttk.Label(line, text="•" * 12 if secret else (value or "—"), style="Panel.TLabel",
                            wraplength=180, font=("Monospace", 10) if secret else None)
            if copy_key and value:
                lbl.bind("<Double-1>", lambda ev: self.copy_field(copy_key))
            if secret:
                def toggle():
                    showing = lbl.cget("text") == value
                    lbl.configure(text="•" * 12 if showing else value)
                    btn.configure(text="Show" if showing else "Hide")
                btn = ttk.Button(line, text="Show", width=5, command=toggle)
                btn.pack(side="right", padx=4)
            lbl.pack(side="left", fill="x", expand=True)

        row("USERNAME", e.username, "username")
        row("PASSWORD", e.password, "password", secret=True)
        row("URL", e.url, "url")
        if e.notes:
            row("NOTES", e.notes, "notes")
        if e.attachments:
            ttk.Label(d, text="ATTACHMENTS", style="PanelMuted.TLabel", font=("Sans", 8, "bold")).pack(anchor="w")
            for a in e.attachments:
                line = ttk.Frame(d, style="Panel.TFrame")
                line.pack(fill="x", pady=(0, 2))
                ttk.Button(line, text="Save…", style="Small.TButton",
                           command=lambda a=a: self.save_attachment(a)).pack(side="right")
                ttk.Label(line, text="📎 " + a.filename, style="Panel.TLabel", wraplength=200).pack(side="left")
        times = [("Created", e.ctime), ("Modified", e.mtime), ("Accessed", e.atime)]
        if e.expires:
            times.append(("Expired" if e.expired else "Expires", e.expiry_time))
        ttk.Label(d, text="\n".join(f"{k:<9} {pwvault.fmt_time(t)}" for k, t in times),
                  style="PanelMuted.TLabel", font=("Monospace", 8), justify="left").pack(anchor="w", pady=(8, 12))
        btns = ttk.Frame(d, style="Panel.TFrame")
        btns.pack(fill="x", side="bottom")
        if in_bin:
            ttk.Button(btns, text="Restore", command=self.restore_selected).pack(side="left")
            ttk.Button(btns, text="Delete forever", style="Danger.TButton",
                       command=self.delete_selected).pack(side="right")
        else:
            ttk.Button(btns, text="Edit", command=self.edit_selected).pack(side="left")
            ttk.Button(btns, text=f"History ({len(e.history)})",
                       command=lambda: HistoryDialog(self, e)).pack(side="left", padx=4)
            ttk.Button(btns, text="Delete", style="Danger.TButton", command=self.delete_selected).pack(side="right")

    def copy_field(self, key):
        e = self.selected()
        if e:
            e.touch()  # access time, written with the next save
            self.copy(getattr(e, key) or "", key.capitalize())

    def shortcut_copy(self, key, event):
        # Inside a text field with a selection, let Ctrl+C do a normal copy.
        w = event.widget
        if isinstance(w, (ttk.Entry, tk.Entry)) and w.selection_present():
            return
        if isinstance(w, tk.Text) and w.tag_ranges("sel"):
            return
        self.copy_field(key)
        return "break"

    def save_attachment(self, att):
        path = filedialog.asksaveasfilename(parent=self.root, title="Save attachment", initialfile=att.filename)
        if not path:
            return
        try:
            pwvault.write_private(Path(path), att.data)
            self.status(f"Saved {Path(path).name} (readable only by you).")
        except OSError as e:
            messagebox.showerror("Save attachment", str(e), parent=self.root)

    def add_entry(self):
        if self.vault is None:  # Ctrl+N on the unlock screen
            return
        group = self.current_group
        if group is None or self.vault.in_recycle_bin(group):
            group = self.vault.root
        EntryDialog(self, group=group)

    def edit_selected(self):
        e = self.selected()
        if e and not self.vault.in_recycle_bin(e):
            EntryDialog(self, e)

    def delete_selected(self):
        e = self.selected()
        if not e:
            return
        permanent = self.vault.in_recycle_bin(e)
        question = (f"Permanently delete '{e.title}'?\nThis cannot be undone." if permanent
                    else f"Move '{e.title}' ({e.username}) to the recycle bin?")
        if not messagebox.askyesno("Delete entry", question, icon="warning", parent=self.root):
            return
        if self.vault is None:  # auto-locked while the dialog was open
            return
        self.vault.delete_entry(e)
        if self.save():
            self.refresh_groups()
            self.status(f"Deleted '{e.title}'." if permanent else f"Moved '{e.title}' to the recycle bin.")

    def restore_selected(self):
        e = self.selected()
        if not e:
            return
        self.vault.restore_entry(e)
        if self.save():
            self.show_group(self.vault.root, select=e)
            self.status(f"Restored '{e.title}' to {self.vault.root.name}.")

    # ---------------------------------------------------------- database menu

    def database_menu(self):
        m = tk.Menu(self.root, tearoff=0, bg=PANEL, fg=FG, activebackground=ACCENT, activeforeground="#fff")
        m.add_command(label="Import CSV…", command=self.import_csv)
        exp = tk.Menu(m, tearoff=0, bg=PANEL, fg=FG, activebackground=ACCENT, activeforeground="#fff")
        for fmt in pwvault.EXPORT_FORMATS:
            exp.add_command(label=fmt.upper() + ("  (KeePass XML)" if fmt == "xml" else ""),
                            command=lambda f=fmt: self.export(f))
        m.add_cascade(label="Export", menu=exp)
        m.add_separator()
        m.add_command(label="Empty recycle bin…", command=self.empty_bin)
        m.add_command(label="Change master key…", command=lambda: ChangeMasterDialog(self))
        m.add_separator()
        m.add_command(label="Open other database…", command=self.open_other)
        m.add_command(label="New database…", command=self.new_vault)
        m.add_command(label="Show file location", command=lambda: messagebox.showinfo(
            "Vault file", f"{self.vault.path}\n\nIt's an encrypted KeePass file — safe to back up anywhere, "
            "and it opens in KeePassXC too." + (f"\n\nKey file: {self.vault.kp.keyfile}" if self.vault.kp.keyfile else ""),
            parent=self.root))
        b = self.db_btn
        m.tk_popup(b.winfo_rootx(), b.winfo_rooty() + b.winfo_height())

    def empty_bin(self):
        if not messagebox.askyesno("Empty recycle bin", "Permanently delete everything in the recycle bin?",
                                   icon="warning", parent=self.root) or self.vault is None:
            return
        n = self.vault.empty_recycle_bin()
        if self.save():
            self.refresh_groups()
            self.status(f"Permanently deleted {n} item{'s' if n != 1 else ''}.")

    def export(self, fmt):
        if not messagebox.askokcancel("Export", f"{pwvault.EXPORT_WARNING}\n\nContinue?", icon="warning",
                                      parent=self.root):
            return
        path = filedialog.asksaveasfilename(parent=self.root, title=f"Export as {fmt.upper()}",
                                            initialfile=f"pwvault-export.{fmt}", defaultextension="." + fmt)
        if not path or self.vault is None:
            return
        try:
            n = pwvault.export(self.vault, Path(path), fmt)
        except (VaultError, OSError) as e:
            return messagebox.showerror("Export failed", str(e), parent=self.root)
        self.status(f"Exported {n} entries to {Path(path).name} — delete it when you're done.")

    def import_csv(self):
        path = filedialog.askopenfilename(
            parent=self.root, title="Select a browser or password-manager CSV export",
            initialdir=str(Path.home() / "Downloads"),
            filetypes=[("CSV files", "*.csv"), ("All files", "*")])
        if not path or self.vault is None:  # cancelled, or auto-locked while the dialog was open
            return
        path = Path(path)
        try:
            records = pwvault.read_csv_export(path)
        except (VaultError, OSError, UnicodeDecodeError) as e:
            return messagebox.showerror("Import failed", str(e), parent=self.root)
        added, updated = pwvault.merge_records(self.vault, records)
        if not self.save():
            return
        self.refresh_groups()
        msg = (f"Imported {len(records)} rows: {added} new, {updated} updated, "
               f"{len(records) - added - updated} unchanged.\n\n"
               f"{path.name} still contains your passwords in plain text.\n"
               f"Delete it now?")
        if messagebox.askyesno("Import complete", msg, parent=self.root):
            try:
                pwvault.shred(path)
                self.status(f"Imported and deleted {path.name}.")
                messagebox.showinfo("CSV deleted", pwvault.SHRED_CAVEAT, parent=self.root)
            except OSError as e:
                messagebox.showerror("Couldn't delete", str(e), parent=self.root)
        else:
            self.status(f"Imported {path.name} — remember to delete it.")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    os.umask(0o077)
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else pwvault.DEFAULT_VAULT
    App(path).run()
