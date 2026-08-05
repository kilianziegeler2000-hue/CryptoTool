#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import ctypes
import shutil
import struct
import sys
import threading
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog

try:
    import customtkinter as ctk
    from tkinterdnd2 import DND_FILES, TkinterDnD
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
except ImportError as error:
    print(
        "Fehlende Bibliothek.\n"
        "Installiere alles mit:\n"
        "python -m pip install pycryptodome customtkinter tkinterdnd2\n\n"
        f"Details: {error}",
        file=sys.stderr,
    )
    raise SystemExit(2)


MAGIC = b"CT01"
HEADER = struct.Struct(">4sHBBQ")
AES_KEY_SIZE = 32
HASH_CHUNK_SIZE = 1024 * 1024
ACTIVITY_LOG = Path.cwd() / "cryptotool_activity.log"
RANSOM_NOTE_NAMES = {
    "decrypt.txt",
    "decrypt_files.txt",
    "how_to_decrypt.txt",
    "how_to_restore_files.txt",
    "restore_files.txt",
    "ransom_note.txt",
}
SUSPICIOUS_ENCRYPTED_SUFFIXES = {
    ".locked",
    ".encrypted",
    ".crypted",
    ".crypt",
    ".lockbit",
    ".ryuk",
    ".wncry",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(HASH_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def write_activity(action: str, target: Path, result: str) -> None:
    """Protokolliert nur Metadaten, niemals Schlüssel oder Dateiinhalte."""

    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    safe_action = action.replace("\n", " ")
    safe_result = result.replace("\n", " ")
    with ACTIVITY_LOG.open("a", encoding="utf-8") as log:
        log.write(f"{timestamp}\t{safe_action}\t{target}\t{safe_result}\n")


def create_backup(source: Path, backup_folder: Path) -> Path:
    if not source.is_file():
        raise ValueError("Sicherheitskopien werden nur für einzelne Dateien erstellt.")
    backup_folder.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    destination = backup_folder / f"{source.name}.{timestamp}.backup"
    shutil.copy2(source, destination)
    if sha256_file(source) != sha256_file(destination):
        destination.unlink(missing_ok=True)
        raise OSError("Die Prüfsumme der Sicherheitskopie stimmt nicht.")
    return destination


def keys_match(
    public_key_path: Path,
    private_key_path: Path,
    passphrase: str | None = None,
) -> bool:
    public_key = RSA.import_key(public_key_path.read_bytes()).public_key()
    private_key = RSA.import_key(
        private_key_path.read_bytes(), passphrase=passphrase
    )
    if not private_key.has_private():
        raise ValueError("Der ausgewählte private Schlüssel enthält keinen Privatanteil.")
    return public_key.n == private_key.n and public_key.e == private_key.e


def find_ransomware_indicators(path: Path) -> list[str]:
    """Sucht konservativ nach sichtbaren Hinweisen, ohne etwas zu verändern."""

    indicators: list[str] = []
    with path.open("rb") as source:
        is_cryptotool_file = source.read(len(MAGIC)) == MAGIC

    if path.suffix.casefold() in SUSPICIOUS_ENCRYPTED_SUFFIXES:
        indicators.append(f"verdächtige Dateiendung {path.suffix}")

    notes = sorted(
        candidate.name
        for candidate in path.parent.iterdir()
        if candidate.is_file()
        and candidate.name.casefold() in RANSOM_NOTE_NAMES
        and candidate != path
    )
    if notes:
        indicators.append("mögliche Lösegeldnotiz: " + ", ".join(notes))

    if is_cryptotool_file:
        return []
    return indicators


def analyze_target(target: Path, progress_callback=None) -> tuple[str, list[str]]:
    """Analysiert eine Datei oder einen Ordner rekursiv."""

    if target.is_file():
        indicators = find_ransomware_indicators(target)
        result = analyze_suspicious_file(target), indicators
        if progress_callback:
            progress_callback(1, 1, f"Geprüft: {target.name}")
        return result

    if not target.is_dir():
        raise FileNotFoundError(f"Datei oder Ordner nicht gefunden:\n{target}")

    files = sorted(
        path for path in target.rglob("*")
        if path.is_file() and not path.is_symlink()
    )
    findings: list[str] = []
    errors: list[str] = []

    for index, path in enumerate(files, start=1):
        try:
            relative = path.relative_to(target)
            if path.name.casefold() in RANSOM_NOTE_NAMES:
                findings.append(f"{relative}: mögliche Lösegeldnotiz")
                continue
            with path.open("rb") as source:
                is_cryptotool_file = source.read(len(MAGIC)) == MAGIC
            if (
                not is_cryptotool_file
                and path.suffix.casefold() in SUSPICIOUS_ENCRYPTED_SUFFIXES
            ):
                findings.append(
                    f"{relative}: verdächtige Dateiendung {path.suffix}"
                )
        except OSError as error:
            errors.append(f"{path}: {error}")
        finally:
            if progress_callback:
                progress_callback(index, len(files), f"Prüfe {path.name}")

    assessment = (
        f"{len(findings)} typische Hinweise gefunden."
        if findings
        else "Keine typischen Ransomware-Hinweise gefunden."
    )
    finding_text = "\n".join(f"- {item}" for item in findings) or "- Keine"
    error_text = "\n".join(f"- {item}" for item in errors) or "- Keine"
    report = "\n".join(
        (
            "CryptoTool – Ransomware-Ordnerdiagnose",
            "=======================================",
            "",
            f"Ordner: {target}",
            f"Geprüfte Dateien: {len(files)}",
            f"Bewertung: {assessment}",
            "",
            "GEFUNDENE HINWEISE:",
            finding_text,
            "",
            "NICHT LESBARE DATEIEN:",
            error_text,
            "",
            "EMPFOHLENES WERKZEUG:",
            "No More Ransom – Crypto Sheriff:",
            "https://www.nomoreransom.org/crypto-sheriff.php",
            "",
            "Die Prüfung verändert keine untersuchte Datei.",
            "Keine typischen Hinweise sind keine Garantie für ein sauberes System.",
        )
    )
    return report, findings


def analyze_suspicious_file(path: Path) -> str:
    """Erstellt einen rein lesenden Diagnosebericht für eine verdächtige Datei."""

    if not path.is_file():
        raise FileNotFoundError(f"Datei nicht gefunden:\n{path}")

    digest = hashlib.sha256()
    with path.open("rb") as source:
        header = source.read(max(HEADER.size, 16))
        digest.update(header)
        while chunk := source.read(HASH_CHUNK_SIZE):
            digest.update(chunk)

    if header.startswith(MAGIC):
        file_type = (
            "CryptoTool-Datei (CT01). Sie kann mit diesem Programm und dem "
            "passenden priv.key entschlüsselt werden."
        )
        recommendations = (
            "1. In CryptoTool auf 'Entschlüsseln' klicken.\n"
            "2. Den zu dieser Datei gehörenden priv.key auswählen.\n"
            "3. Falls der Schlüssel fehlt, kann CryptoTool ihn nicht ersetzen."
        )
    elif header.startswith(b"PK\x03\x04"):
        file_type = "ZIP-/Office-Container; keine Ransomware eindeutig erkennbar."
        recommendations = (
            "1. Dateiendung und Originalprogramm prüfen.\n"
            "2. Die Datei nicht mit zufälligen Entschlüsslern verändern.\n"
            "3. Bei zusätzlicher unbekannter Endung Crypto Sheriff verwenden."
        )
    elif header.startswith(b"%PDF-"):
        file_type = "PDF-Datei; keine Ransomware eindeutig erkennbar."
        recommendations = (
            "1. Eine Kopie mit einem aktuellen PDF-Reader öffnen.\n"
            "2. Bei zusätzlicher unbekannter Endung Crypto Sheriff verwenden."
        )
    else:
        file_type = "Unbekanntes Format; daraus folgt nicht automatisch Ransomware."
        recommendations = (
            "1. No More Ransom – Crypto Sheriff zur Identifikation verwenden:\n"
            "   https://www.nomoreransom.org/crypto-sheriff.php\n"
            "2. Danach ausschließlich einen dort vorgeschlagenen Decryptor nutzen:\n"
            "   https://www.nomoreransom.org/en/decryption-tools.html\n"
            "3. Vor jedem Versuch eine unveränderte Kopie sichern."
        )

    notes = sorted(
        candidate.name
        for candidate in path.parent.iterdir()
        if candidate.is_file()
        and candidate.name.casefold() in RANSOM_NOTE_NAMES
        and candidate != path
    )
    note_text = ", ".join(notes) if notes else "Keine typische Lösegeldnotiz gefunden"

    indicators = find_ransomware_indicators(path)
    assessment = (
        "Typische Ransomware-Hinweise gefunden: " + "; ".join(indicators)
        if indicators
        else "Keine typischen Ransomware-Hinweise gefunden."
    )

    return "\n".join(
        (
            "CryptoTool – Ransomware-Diagnose",
            "=================================",
            "",
            f"Datei: {path}",
            f"Größe: {path.stat().st_size} Bytes",
            f"Dateiendung: {path.suffix or '(keine)'}",
            f"SHA-256: {digest.hexdigest()}",
            f"Erkennung: {file_type}",
            f"Bewertung: {assessment}",
            f"Hinweisdateien im Ordner: {note_text}",
            "",
            "EMPFOHLENE WERKZEUGE / NÄCHSTE SCHRITTE:",
            recommendations,
            "",
            "WICHTIG:",
            "- Die untersuchte Datei wurde nicht verändert.",
            "- Keine verdächtigen Programme ausführen.",
            "- Betroffenen Rechner vom Netzwerk trennen.",
            "- Originaldateien und Lösegeldnotiz für die Analyse aufbewahren.",
            "- Nach bekannten Entschlüsslern auf https://www.nomoreransom.org suchen.",
            "- Ein unbekanntes Format beweist keine Infektion.",
        )
    )


def confirm_overwrite(path: Path) -> bool:
    if not path.exists():
        return True

    return messagebox.askyesno(
        "Datei überschreiben?",
        f"Diese Datei existiert bereits:\n\n{path}\n\n"
        "Soll sie überschrieben werden?",
    )


def generate_keys(
    private_path: Path,
    public_path: Path,
    passphrase: str | None = None,
    confirm: bool = True,
) -> bool:
    if confirm and not confirm_overwrite(private_path):
        return False
    if confirm and not confirm_overwrite(public_path):
        return False

    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    key = RSA.generate(3072)

    export_options = {
        "format": "PEM",
        "passphrase": passphrase,
        "pkcs": 8,
    }
    if passphrase:
        export_options["protection"] = "scryptAndAES128-CBC"
    private_path.write_bytes(key.export_key(**export_options))
    public_path.write_bytes(
        key.public_key().export_key(format="PEM")
    )
    return True


def encrypt_file(
    source: Path,
    public_key_path: Path,
    output: Path,
    confirm: bool = True,
) -> bool:
    if not source.is_file():
        raise FileNotFoundError(f"Datei nicht gefunden:\n{source}")

    if not public_key_path.is_file():
        raise FileNotFoundError(
            f"Öffentlicher Schlüssel nicht gefunden:\n{public_key_path}"
        )

    if source.resolve() == output.resolve():
        raise ValueError("Eingabe- und Ausgabedatei dürfen nicht identisch sein.")

    if confirm and not confirm_overwrite(output):
        return False

    output.parent.mkdir(parents=True, exist_ok=True)

    public_key = RSA.import_key(public_key_path.read_bytes())
    if public_key.has_private():
        public_key = public_key.public_key()

    plaintext = source.read_bytes()
    aes_key = get_random_bytes(AES_KEY_SIZE)

    aes_cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext)

    rsa_cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)

    header = HEADER.pack(
        MAGIC,
        len(encrypted_aes_key),
        len(aes_cipher.nonce),
        len(tag),
        len(plaintext),
    )

    temporary = output.with_name(output.name + ".tmp")

    try:
        temporary.write_bytes(
            header
            + encrypted_aes_key
            + aes_cipher.nonce
            + tag
            + ciphertext
        )
        temporary.replace(output)
    finally:
        if temporary.exists():
            temporary.unlink()
    return True


def decrypt_file(
    source: Path,
    private_key_path: Path,
    output: Path,
    passphrase: str | None = None,
    confirm: bool = True,
) -> bool:
    if not source.is_file():
        raise FileNotFoundError(f"Datei nicht gefunden:\n{source}")

    if not private_key_path.is_file():
        raise FileNotFoundError(
            f"Privater Schlüssel nicht gefunden:\n{private_key_path}"
        )

    if source.resolve() == output.resolve():
        raise ValueError("Eingabe- und Ausgabedatei dürfen nicht identisch sein.")

    if confirm and not confirm_overwrite(output):
        return False

    output.parent.mkdir(parents=True, exist_ok=True)

    blob = source.read_bytes()

    if len(blob) < HEADER.size:
        raise ValueError("Die Datei ist zu kurz oder beschädigt.")

    magic, enc_key_len, nonce_len, tag_len, original_size = HEADER.unpack_from(blob)

    if magic != MAGIC:
        raise ValueError(
            "Unbekanntes Dateiformat.\n"
            "Die Datei wurde vermutlich nicht mit diesem Tool erstellt."
        )

    offset = HEADER.size
    minimum_size = offset + enc_key_len + nonce_len + tag_len

    if len(blob) < minimum_size:
        raise ValueError("Die Datei ist unvollständig oder beschädigt.")

    encrypted_aes_key = blob[offset:offset + enc_key_len]
    offset += enc_key_len

    nonce = blob[offset:offset + nonce_len]
    offset += nonce_len

    tag = blob[offset:offset + tag_len]
    offset += tag_len

    ciphertext = blob[offset:]

    private_key = RSA.import_key(
        private_key_path.read_bytes(), passphrase=passphrase
    )

    if not private_key.has_private():
        raise ValueError(
            "Der ausgewählte Schlüssel ist kein privater RSA-Schlüssel."
        )

    rsa_cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)

    aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    plaintext = aes_cipher.decrypt_and_verify(ciphertext, tag)

    if len(plaintext) != original_size:
        raise ValueError(
            "Die entschlüsselte Dateigröße stimmt nicht."
        )

    temporary = output.with_name(output.name + ".tmp")

    try:
        temporary.write_bytes(plaintext)
        temporary.replace(output)
    finally:
        if temporary.exists():
            temporary.unlink()
    if hashlib.sha256(plaintext).hexdigest() != sha256_file(output):
        output.unlink(missing_ok=True)
        raise OSError("Integritätsprüfung der entschlüsselten Datei fehlgeschlagen.")
    return True


class HoverTooltip:
    """Zeigt Hover-Hilfe in einem festen Feld statt in einem Popup-Fenster."""

    def __init__(self, widget, text: str, display_label) -> None:
        self.widget = widget
        self.text = text
        self.display_label = display_label
        self.visible = False
        self.watch_id = None
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)

    def show(self, _event=None) -> None:
        self.display_label._tooltip_owner = self
        self.display_label.configure(text=self.text)
        if not self.display_label.winfo_manager():
            pack_options = {"fill": "x", "padx": 18, "pady": (0, 12)}
            before_widget = getattr(self.display_label, "_pack_before", None)
            if before_widget is not None:
                pack_options["before"] = before_widget
            self.display_label.pack(**pack_options)
        self.visible = True
        self._watch_pointer()

    def _watch_pointer(self) -> None:
        if not self.visible:
            return
        pointer_x = self.widget.winfo_pointerx()
        pointer_y = self.widget.winfo_pointery()
        left = self.widget.winfo_rootx()
        top = self.widget.winfo_rooty()
        is_inside = (
            left <= pointer_x < left + self.widget.winfo_width()
            and top <= pointer_y < top + self.widget.winfo_height()
        )
        if not is_inside:
            self.hide()
            return
        self.watch_id = self.widget.after(60, self._watch_pointer)

    def hide(self, _event=None) -> None:
        if self.watch_id is not None:
            try:
                self.widget.after_cancel(self.watch_id)
            except Exception:
                pass
            self.watch_id = None
        self.visible = False
        if getattr(self.display_label, "_tooltip_owner", None) is self:
            self.display_label.pack_forget()
            self.display_label.configure(text="")
            self.display_label._tooltip_owner = None


class CryptoApp(TkinterDnD.Tk):
    def __init__(self) -> None:
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("CryptoTool Modern")
        self.geometry("900x850")
        self.minsize(820, 760)
        self.configure(bg="#080d18")
        self.after(0, self._enable_dark_window_chrome)

        self.selected_file: Path | None = None
        self.public_key = Path.cwd() / "pub.key"
        self.private_key = Path.cwd() / "priv.key"
        self.backup_folder: Path | None = None
        self.backup_enabled = ctk.BooleanVar(value=False)
        self.busy = False
        self.tooltips: list[HoverTooltip] = []

        self._build_ui()
        self._register_drop_zone()
        self.bind_all("<Motion>", self._handle_global_pointer, add="+")
        self.bind_all("<ButtonPress>", self._hide_all_tooltips, add="+")
        self.bind("<Leave>", self._handle_window_leave, add="+")

    def _enable_dark_window_chrome(self) -> None:
        """Faerbt den nativen Windows-Rahmen passend zur dunklen Oberfläche."""

        if sys.platform != "win32":
            return
        try:
            self.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
            if not hwnd:
                hwnd = self.winfo_id()

            enabled = ctypes.c_int(1)
            # Windows 10/11 verwenden je nach Build Attribut 19 oder 20.
            for attribute in (20, 19):
                result = ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd,
                    attribute,
                    ctypes.byref(enabled),
                    ctypes.sizeof(enabled),
                )
                if result == 0:
                    break

            # COLORREF ist 0x00BBGGRR. Beide Farben entsprechen #080d18.
            dark_color = ctypes.c_uint(0x00180D08)
            for attribute in (34, 35):  # Rahmen- und Titelleistenfarbe
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd,
                    attribute,
                    ctypes.byref(dark_color),
                    ctypes.sizeof(dark_color),
                )
        except (AttributeError, OSError):
            # Auf älteren Windows-Versionen bleibt die normale Systemleiste aktiv.
            pass

    def _build_ui(self) -> None:
        self.configure(bg="#080d18")

        self.main = ctk.CTkFrame(
            self,
            corner_radius=24,
            fg_color="#101827",
            border_width=1,
            border_color="#26334a",
        )
        self.main.pack(fill="both", expand=True, padx=24, pady=24)

        self.title_label = ctk.CTkLabel(
            self.main,
            text="🔐  CryptoTool",
            font=ctk.CTkFont(size=34, weight="bold"),
            text_color="#f8fafc",
        )
        self.title_label.pack(pady=(24, 4))

        self.subtitle = ctk.CTkLabel(
            self.main,
            text="Dateien sicher verschlüsseln und entschlüsseln",
            font=ctk.CTkFont(size=15),
            text_color="#94a3b8",
        )
        self.subtitle.pack(pady=(0, 10))

        self.security_badge = ctk.CTkLabel(
            self.main,
            text="  AES-256-EAX   •   RSA-OAEP   •   vollständig offline  ",
            height=28,
            corner_radius=14,
            fg_color="#172554",
            text_color="#93c5fd",
            font=ctk.CTkFont(size=12, weight="bold"),
        )
        self.security_badge.pack(pady=(0, 18))

        self.drop_frame = ctk.CTkFrame(
            self.main,
            height=155,
            corner_radius=18,
            border_width=2,
            border_color="#3b82f6",
            fg_color="#111d31",
        )
        self.drop_frame.pack(fill="x", padx=30, pady=(0, 20))
        self.drop_frame.pack_propagate(False)

        self.drop_label = ctk.CTkLabel(
            self.drop_frame,
            text="↓\nDatei oder Ordner hier ablegen\noder über die Schaltflächen auswählen",
            font=ctk.CTkFont(size=19, weight="bold"),
            text_color="#dbeafe",
            justify="center",
        )
        self.drop_label.pack(expand=True)

        self.selected_label = ctk.CTkLabel(
            self.main,
            text="  Keine Datei oder kein Ordner ausgewählt",
            font=ctk.CTkFont(size=13),
            text_color="#94a3b8",
            fg_color="#172033",
            corner_radius=10,
            height=38,
            anchor="w",
        )
        self.selected_label.pack(fill="x", padx=30, pady=(0, 14))

        self.scan_result = ctk.CTkLabel(
            self.main,
            text="",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#22c55e",
            wraplength=700,
            corner_radius=12,
            height=10,
        )
        self.scan_result.pack(fill="x", padx=30, pady=(0, 8))

        self.action_row = ctk.CTkFrame(self.main, fg_color="transparent")
        self.action_row.pack(pady=(0, 20))

        self.choose_button = ctk.CTkButton(
            self.action_row,
            text="Datei auswählen",
            width=170,
            height=42,
            corner_radius=12,
            command=self.choose_file,
            fg_color="#2563eb",
            hover_color="#1d4ed8",
        )
        self.choose_button.grid(row=0, column=0, padx=8)

        self.encrypt_button = ctk.CTkButton(
            self.action_row,
            text="Verschlüsseln",
            width=170,
            height=42,
            corner_radius=12,
            command=self.encrypt_selected,
            fg_color="#059669",
            hover_color="#047857",
        )
        self.encrypt_button.grid(row=0, column=1, padx=8)

        self.decrypt_button = ctk.CTkButton(
            self.action_row,
            text="Entschlüsseln",
            width=170,
            height=42,
            corner_radius=12,
            command=self.decrypt_selected,
            fg_color="#7c3aed",
            hover_color="#6d28d9",
        )
        self.decrypt_button.grid(row=0, column=2, padx=8)

        self.folder_button = ctk.CTkButton(
            self.action_row,
            text="Ordner auswählen",
            width=170,
            height=42,
            corner_radius=12,
            command=self.choose_folder,
            fg_color="#334155",
            hover_color="#475569",
        )
        self.folder_button.grid(row=1, column=0, padx=8, pady=(12, 0))

        self.ransomware_button = ctk.CTkButton(
            self.action_row,
            text="Ransomware-Hilfe",
            width=170,
            height=42,
            corner_radius=12,
            fg_color="#d97706",
            hover_color="#b45309",
            command=self.ransomware_help,
        )
        self.ransomware_button.grid(
            row=1, column=1, padx=8, pady=(12, 0)
        )

        self.backup_frame = ctk.CTkFrame(
            self.main,
            fg_color="#132238",
            corner_radius=14,
        )
        self.backup_frame.pack(fill="x", padx=30, pady=(0, 16))

        self.backup_switch = ctk.CTkSwitch(
            self.backup_frame,
            text="Vor Ver-/Entschlüsselung Sicherheitskopie erstellen",
            variable=self.backup_enabled,
        )
        self.backup_switch.pack(side="left", padx=16, pady=12)

        self.backup_button = ctk.CTkButton(
            self.backup_frame,
            text="Backup-Ordner wählen",
            width=170,
            fg_color="#334155",
            hover_color="#475569",
            command=self.choose_backup_folder,
        )
        self.backup_button.pack(side="right", padx=12, pady=8)

        self.key_frame = ctk.CTkFrame(
            self.main,
            corner_radius=16,
            fg_color="#172033",
            border_width=1,
            border_color="#26334a",
        )
        self.key_frame.pack(fill="x", padx=30, pady=(0, 16))

        self.key_title = ctk.CTkLabel(
            self.key_frame,
            text="🔑  Schlüsselverwaltung",
            font=ctk.CTkFont(size=17, weight="bold"),
            text_color="#e2e8f0",
        )
        self.key_title.pack(pady=(16, 10))

        self.key_buttons = ctk.CTkFrame(
            self.key_frame,
            fg_color="transparent",
        )
        self.key_buttons.pack(pady=(0, 14))

        self.key_help_label = ctk.CTkLabel(
            self.key_frame,
            text="",
            wraplength=700,
            justify="left",
            anchor="w",
            corner_radius=10,
            fg_color="#0f172a",
            text_color="#dbeafe",
            font=ctk.CTkFont(size=12),
            padx=12,
            pady=9,
        )

        self.create_keys_button = self._create_key_button(
            text="Schlüsselpaar erstellen",
            command=self.create_keys,
            info=(
                "Erstellt eine neue pub.key und eine passwortgeschützte priv.key. "
                "Mit pub.key wird verschlüsselt, mit priv.key entschlüsselt."
            ),
            row=0,
            column=0,
            width=190,
            fg_color="#2563eb",
            hover_color="#1d4ed8",
        )
        self.public_key_button = self._create_key_button(
            text="pub.key auswählen",
            command=self.choose_public_key,
            info=(
                "Wählt den öffentlichen Schlüssel aus. Er darf weitergegeben "
                "werden und wird zum Verschlüsseln verwendet."
            ),
            row=0,
            column=1,
            width=170,
        )
        self.private_key_button = self._create_key_button(
            text="priv.key auswählen",
            command=self.choose_private_key,
            info=(
                "Wählt den geheimen privaten Schlüssel zum Entschlüsseln aus. "
                "Diese Datei niemals weitergeben oder verlieren."
            ),
            row=0,
            column=2,
            width=170,
        )
        self.check_keys_button = self._create_key_button(
            text="Schlüsselpaar prüfen",
            command=self.check_key_pair,
            info=(
                "Prüft sicher, ob die ausgewählte pub.key und priv.key wirklich "
                "zum selben Schlüsselpaar gehören."
            ),
            row=1,
            column=0,
            columnspan=3,
            width=190,
            fg_color="#0f766e",
            hover_color="#115e59",
            pady=(10, 0),
        )

        self.key_info = ctk.CTkLabel(
            self.key_frame,
            text=self._key_text(),
            font=ctk.CTkFont(size=12),
            text_color="#94a3b8",
            justify="left",
        )
        self.key_info.pack(padx=18, pady=(0, 16), anchor="w")
        self.key_help_label._pack_before = self.key_info

        self.status = ctk.CTkLabel(
            self.main,
            text="Bereit",
            anchor="w",
            height=32,
            corner_radius=10,
            fg_color="#0f172a",
            text_color="#cbd5e1",
        )
        self.status.pack(fill="x", padx=30, pady=(0, 20))

        self.progress = ctk.CTkProgressBar(
            self.main,
            mode="determinate",
            height=8,
            progress_color="#3b82f6",
        )
        self.progress.set(0)
        self.progress_indeterminate = False

        self._busy_widgets = (
            self.choose_button,
            self.folder_button,
            self.encrypt_button,
            self.decrypt_button,
            self.ransomware_button,
            self.backup_button,
            self.create_keys_button,
            self.public_key_button,
            self.private_key_button,
            self.check_keys_button,
        )

    def _create_key_button(
        self,
        *,
        text: str,
        command,
        info: str,
        row: int,
        column: int,
        width: int,
        columnspan: int = 1,
        fg_color: str = "#334155",
        hover_color: str = "#475569",
        pady=0,
    ):
        cell = ctk.CTkFrame(self.key_buttons, fg_color="transparent")
        cell.grid(
            row=row,
            column=column,
            columnspan=columnspan,
            padx=7,
            pady=pady,
        )
        button = ctk.CTkButton(
            cell,
            text=text,
            width=width,
            fg_color=fg_color,
            hover_color=hover_color,
            command=command,
        )
        button.pack(padx=2, pady=2)
        info_badge = ctk.CTkLabel(
            button,
            text="ⓘ",
            width=15,
            height=15,
            corner_radius=0,
            fg_color="transparent",
            text_color="#ffffff",
            font=ctk.CTkFont(size=10, weight="bold"),
            cursor="hand2",
        )
        info_badge.place(relx=1.0, x=-6, y=6, anchor="ne")
        self.tooltips.append(HoverTooltip(info_badge, info, self.key_help_label))
        return button

    def _register_drop_zone(self) -> None:
        for widget in (self.drop_frame, self.drop_label):
            widget.drop_target_register(DND_FILES)
            widget.dnd_bind("<<Drop>>", self.handle_drop)

    def _handle_global_pointer(self, event) -> None:
        for tooltip in self.tooltips:
            if not tooltip.visible:
                continue
            badge = tooltip.widget
            left = badge.winfo_rootx()
            top = badge.winfo_rooty()
            is_over_badge = (
                left <= event.x_root < left + badge.winfo_width()
                and top <= event.y_root < top + badge.winfo_height()
            )
            if not is_over_badge:
                tooltip.hide()

    def _hide_all_tooltips(self, _event=None) -> None:
        for tooltip in self.tooltips:
            tooltip.hide()

    def _handle_window_leave(self, _event=None) -> None:
        self.after(20, self._hide_if_pointer_outside_app)

    def _hide_if_pointer_outside_app(self) -> None:
        x = self.winfo_pointerx()
        y = self.winfo_pointery()
        is_inside = (
            self.winfo_rootx() <= x < self.winfo_rootx() + self.winfo_width()
            and self.winfo_rooty() <= y < self.winfo_rooty() + self.winfo_height()
        )
        if not is_inside:
            self._hide_all_tooltips()

    def _key_text(self) -> str:
        return (
            f"Öffentlicher Schlüssel: {self.public_key}\n"
            f"Privater Schlüssel: {self.private_key}"
        )

    def set_status(self, text: str) -> None:
        self.status.configure(text=f"  {text}")
        self.update_idletasks()

    def run_background(
        self,
        task,
        on_success,
        action: str,
        target: Path,
        *,
        determinate: bool = False,
    ) -> None:
        if self.busy:
            messagebox.showwarning("Bitte warten", "Eine Aktion läuft bereits.")
            return

        self.busy = True
        for widget in self._busy_widgets:
            widget.configure(state="disabled")
        self.progress.pack(fill="x", padx=30, pady=(0, 10), before=self.status)
        self.progress_indeterminate = not determinate
        self.progress.configure(mode="determinate" if determinate else "indeterminate")
        self.progress.set(0)
        if self.progress_indeterminate:
            self.progress.start()

        def worker() -> None:
            try:
                result = task()
            except Exception as error:
                self.after(0, lambda: self._finish_error(error, action, target))
            else:
                self.after(0, lambda: self._finish_success(result, on_success, action, target))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_busy(self) -> None:
        if self.progress_indeterminate:
            self.progress.stop()
        else:
            self.progress.set(1)
        self.progress.pack_forget()
        for widget in self._busy_widgets:
            widget.configure(state="normal")
        self.busy = False

    def report_progress(
        self,
        current: int,
        total: int,
        detail: str = "",
    ) -> None:
        """Überträgt Fortschritt sicher aus einem Hintergrund-Thread in die UI."""

        fraction = 1 if total <= 0 else min(max(current / total, 0), 1)

        def update() -> None:
            self.progress.set(fraction)
            suffix = f" – {detail}" if detail else ""
            self.status.configure(text=f"  {current}/{total}{suffix}")

        self.after(0, update)

    def _finish_error(self, error: Exception, action: str, target: Path) -> None:
        self._finish_busy()
        self.set_status("Fehler")
        try:
            write_activity(action, target, f"FEHLER: {error}")
        except OSError:
            pass
        messagebox.showerror("Fehler", str(error))

    def _finish_success(self, result, on_success, action: str, target: Path) -> None:
        self._finish_busy()
        try:
            write_activity(action, target, "ERFOLGREICH")
        except OSError:
            pass
        on_success(result)

    def ask_private_key_password(self, title: str) -> str | None:
        return simpledialog.askstring(
            title,
            "Passwort des privaten Schlüssels eingeben.\n"
            "Bei alten ungeschützten Schlüsseln leer lassen:",
            show="*",
            parent=self,
        )

    def choose_backup_folder(self) -> None:
        folder = filedialog.askdirectory(title="Ordner für Sicherheitskopien wählen")
        if folder:
            self.backup_folder = Path(folder)
            self.backup_enabled.set(True)
            self.set_status(f"Backup-Ordner: {self.backup_folder}")

    def make_optional_backup(self, source: Path) -> Path | None:
        if not self.backup_enabled.get():
            return None
        if self.backup_folder is None:
            raise ValueError("Bitte zuerst einen Backup-Ordner auswählen.")
        return create_backup(source, self.backup_folder)

    def show_diagnosis(self, report: str, title: str = "Diagnoseübersicht") -> None:
        window = ctk.CTkToplevel(self)
        window.title(title)
        window.geometry("850x620")
        window.minsize(700, 500)
        window.configure(fg_color="#080d18")
        ctk.CTkLabel(
            window,
            text=title,
            font=ctk.CTkFont(size=24, weight="bold"),
        ).pack(padx=20, pady=(20, 10))
        text_box = ctk.CTkTextbox(
            window,
            font=ctk.CTkFont(family="Consolas", size=13),
            fg_color="#101827",
            border_width=1,
            border_color="#26334a",
        )
        text_box.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        text_box.insert("1.0", report)
        text_box.configure(state="disabled")

    def set_selected_file(self, path: str | Path) -> None:
        selected = Path(path)

        if not selected.exists() or not (selected.is_file() or selected.is_dir()):
            messagebox.showerror(
                "Ungültige Auswahl",
                "Bitte wähle eine Datei oder einen Ordner aus.",
            )
            return

        self.selected_file = selected
        kind = "Ordner" if selected.is_dir() else "Datei"
        icon = "📁" if selected.is_dir() else "📄"
        self.selected_label.configure(text=f"  {icon}  {kind}: {selected}")
        self.scan_result.configure(text="", fg_color="transparent", height=10)
        self.set_status(f"{kind} ausgewählt")

    def choose_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Datei auswählen"
        )
        if path:
            self.set_selected_file(path)

    def choose_folder(self) -> None:
        path = filedialog.askdirectory(title="Ordner auswählen")
        if path:
            self.set_selected_file(path)

    def handle_drop(self, event) -> None:
        paths = self.tk.splitlist(event.data)
        if not paths:
            return
        self.set_selected_file(paths[0])

    def create_keys(self) -> None:
        folder = filedialog.askdirectory(
            title="Ordner für Schlüssel auswählen"
        )
        if not folder:
            return

        private_path = Path(folder) / "priv.key"
        public_path = Path(folder) / "pub.key"

        if not confirm_overwrite(private_path) or not confirm_overwrite(public_path):
            self.set_status("Erstellung abgebrochen")
            return

        password = simpledialog.askstring(
            "Privaten Schlüssel schützen",
            "Neues Passwort eingeben (mindestens 8 Zeichen):",
            show="*",
            parent=self,
        )
        if password is None:
            return
        if len(password) < 8:
            messagebox.showwarning(
                "Passwort zu kurz", "Das Passwort muss mindestens 8 Zeichen haben."
            )
            return
        confirmation = simpledialog.askstring(
            "Passwort bestätigen",
            "Passwort erneut eingeben:",
            show="*",
            parent=self,
        )
        if confirmation != password:
            messagebox.showerror("Passwörter stimmen nicht überein", "Abgebrochen.")
            return

        self.set_status("Erstelle passwortgeschützte RSA-Schlüssel ...")

        def task():
            generate_keys(
                private_path, public_path, passphrase=password, confirm=False
            )
            return private_path, public_path

        def finished(result) -> None:
            self.private_key, self.public_key = result
            self.key_info.configure(text=self._key_text())
            self.set_status("Schlüsselpaar erstellt")
            messagebox.showinfo(
                "Fertig",
                "Das Schlüsselpaar wurde erstellt. priv.key ist mit deinem "
                "Passwort geschützt.\n\n"
                "Bewahre priv.key sicher auf.",
            )

        self.run_background(task, finished, "Schlüsselpaar erstellt", private_path)

    def choose_public_key(self) -> None:
        path = filedialog.askopenfilename(
            title="Öffentlichen Schlüssel auswählen",
            filetypes=[
                ("Schlüsseldateien", "*.key"),
                ("Alle Dateien", "*.*"),
            ],
        )
        if path:
            self.public_key = Path(path)
            self.key_info.configure(text=self._key_text())
            self.set_status("Öffentlicher Schlüssel ausgewählt")

    def choose_private_key(self) -> None:
        path = filedialog.askopenfilename(
            title="Privaten Schlüssel auswählen",
            filetypes=[
                ("Schlüsseldateien", "*.key"),
                ("Alle Dateien", "*.*"),
            ],
        )
        if path:
            self.private_key = Path(path)
            self.key_info.configure(text=self._key_text())
            self.set_status("Privater Schlüssel ausgewählt")

    def check_key_pair(self) -> None:
        if not self.public_key.is_file() or not self.private_key.is_file():
            messagebox.showwarning(
                "Schlüssel fehlen",
                "Bitte zuerst einen öffentlichen und privaten Schlüssel auswählen.",
            )
            return
        password = self.ask_private_key_password("Schlüsselpaar prüfen")
        if password is None:
            return
        self.set_status("Prüfe Schlüsselpaar ...")

        def finished(matches: bool) -> None:
            if matches:
                self.set_status("Schlüssel gehören zusammen")
                messagebox.showinfo(
                    "Schlüsselpaar gültig",
                    "✓ pub.key und priv.key gehören zusammen.",
                )
            else:
                self.set_status("Schlüssel passen nicht zusammen")
                messagebox.showwarning(
                    "Falsches Schlüsselpaar",
                    "pub.key und priv.key gehören NICHT zusammen.",
                )

        self.run_background(
            lambda: keys_match(self.public_key, self.private_key, password or None),
            finished,
            "Schlüsselpaar geprüft",
            self.private_key,
        )

    @staticmethod
    def _folder_files(folder: Path, *, encrypted_only: bool = False) -> list[Path]:
        files = [
            path
            for path in folder.rglob("*")
            if path.is_file() and not path.is_symlink()
        ]
        if encrypted_only:
            files = [path for path in files if path.suffix.casefold() == ".enc"]
        return sorted(files)

    def _folder_output_root(self, source: Path, suffix: str, title: str) -> Path | None:
        parent = filedialog.askdirectory(title=title)
        if not parent:
            return None
        output_root = Path(parent) / f"{source.name}{suffix}"
        try:
            if output_root.resolve().is_relative_to(source.resolve()):
                messagebox.showwarning(
                    "Ungültiger Zielordner",
                    "Der Ausgabeordner darf nicht innerhalb des Quellordners liegen.",
                )
                return None
        except OSError:
            pass
        if output_root.exists() and not messagebox.askyesno(
            "Ausgabeordner existiert",
            f"Der Ausgabeordner existiert bereits:\n\n{output_root}\n\n"
            "Vorhandene gleichnamige Ergebnisdateien überschreiben?",
        ):
            return None
        return output_root

    def encrypt_selected_folder(self, source: Path) -> None:
        output_root = self._folder_output_root(
            source,
            "_encrypted",
            "Ziel für den verschlüsselten Ordner wählen",
        )
        if output_root is None:
            return
        backup_folder = self.backup_folder if self.backup_enabled.get() else None
        if self.backup_enabled.get() and backup_folder is None:
            messagebox.showwarning(
                "Backup-Ordner fehlt", "Bitte zuerst einen Backup-Ordner auswählen."
            )
            return
        self.set_status("Bereite Ordnerverschlüsselung vor ...")

        def task():
            files = self._folder_files(source)
            if not files:
                raise ValueError("Der ausgewählte Ordner enthält keine Dateien.")
            successes = 0
            errors: list[str] = []
            for index, path in enumerate(files, start=1):
                relative = path.relative_to(source)
                destination = output_root / relative.parent / f"{relative.name}.enc"
                try:
                    if backup_folder:
                        create_backup(path, backup_folder)
                    encrypt_file(path, self.public_key, destination, confirm=False)
                    successes += 1
                except Exception as error:
                    errors.append(f"{relative}: {error}")
                self.report_progress(index, len(files), relative.as_posix())
            if successes == 0:
                raise RuntimeError("Keine Datei konnte verschlüsselt werden.\n" + "\n".join(errors[:5]))
            return successes, len(files), errors

        def finished(result) -> None:
            successes, total, errors = result
            self.set_status("Ordnerverschlüsselung abgeschlossen")
            details = (
                f"\n\nNicht verarbeitet: {len(errors)}"
                + ("\n" + "\n".join(errors[:5]) if errors else "")
            )
            messagebox.showinfo(
                "Ordner verschlüsselt",
                f"{successes} von {total} Dateien wurden verschlüsselt.\n\n"
                f"Ausgabe:\n{output_root}{details}",
            )

        self.run_background(
            task,
            finished,
            "Ordner verschlüsselt",
            source,
            determinate=True,
        )

    def decrypt_selected_folder(self, source: Path) -> None:
        output_root = self._folder_output_root(
            source,
            "_decrypted",
            "Ziel für den entschlüsselten Ordner wählen",
        )
        if output_root is None:
            return
        password = self.ask_private_key_password("Ordner entschlüsseln")
        if password is None:
            return
        backup_folder = self.backup_folder if self.backup_enabled.get() else None
        if self.backup_enabled.get() and backup_folder is None:
            messagebox.showwarning(
                "Backup-Ordner fehlt", "Bitte zuerst einen Backup-Ordner auswählen."
            )
            return
        self.set_status("Bereite Ordnerentschlüsselung vor ...")

        def task():
            files = self._folder_files(source, encrypted_only=True)
            if not files:
                raise ValueError("Der ausgewählte Ordner enthält keine .enc-Dateien.")
            successes = 0
            errors: list[str] = []
            for index, path in enumerate(files, start=1):
                relative = path.relative_to(source)
                restored_name = relative.name[:-4]
                destination = output_root / relative.parent / restored_name
                try:
                    if backup_folder:
                        create_backup(path, backup_folder)
                    decrypt_file(
                        path,
                        self.private_key,
                        destination,
                        passphrase=password or None,
                        confirm=False,
                    )
                    successes += 1
                except Exception as error:
                    errors.append(f"{relative}: {error}")
                self.report_progress(index, len(files), relative.as_posix())
            if successes == 0:
                raise RuntimeError("Keine Datei konnte entschlüsselt werden.\n" + "\n".join(errors[:5]))
            return successes, len(files), errors

        def finished(result) -> None:
            successes, total, errors = result
            self.set_status("Ordnerentschlüsselung abgeschlossen")
            details = (
                f"\n\nNicht verarbeitet: {len(errors)}"
                + ("\n" + "\n".join(errors[:5]) if errors else "")
            )
            messagebox.showinfo(
                "Ordner entschlüsselt",
                f"{successes} von {total} Dateien wurden entschlüsselt.\n\n"
                f"Ausgabe:\n{output_root}{details}",
            )

        self.run_background(
            task,
            finished,
            "Ordner entschlüsselt",
            source,
            determinate=True,
        )

    def encrypt_selected(self) -> None:
        if self.selected_file is None:
            messagebox.showwarning(
                "Keine Datei",
                "Wähle zuerst eine Datei aus.",
            )
            return
        if self.selected_file.is_dir():
            self.encrypt_selected_folder(self.selected_file)
            return

        output = filedialog.asksaveasfilename(
            title="Verschlüsselte Datei speichern",
            initialfile=self.selected_file.name + ".enc",
            defaultextension=".enc",
            filetypes=[
                ("Verschlüsselte Dateien", "*.enc"),
                ("Alle Dateien", "*.*"),
            ],
        )

        if not output:
            return

        output_path = Path(output)
        if not confirm_overwrite(output_path):
            self.set_status("Verschlüsselung abgebrochen")
            return
        source = self.selected_file
        backup_folder = self.backup_folder if self.backup_enabled.get() else None
        if self.backup_enabled.get() and backup_folder is None:
            messagebox.showwarning(
                "Backup-Ordner fehlt", "Bitte zuerst einen Backup-Ordner auswählen."
            )
            return
        self.set_status("Verschlüssele Datei im Hintergrund ...")

        def task():
            self.report_progress(0, 3, "Sicherheitskopie")
            backup = create_backup(source, backup_folder) if backup_folder else None
            self.report_progress(1, 3, "Original wird geprüft")
            source_hash = sha256_file(source)
            encrypt_file(source, self.public_key, output_path, confirm=False)
            self.report_progress(2, 3, "Ergebnis wird geprüft")
            result = backup, source_hash, sha256_file(output_path)
            self.report_progress(3, 3, "Fertig")
            return result

        def finished(result) -> None:
            backup, source_hash, encrypted_hash = result
            self.set_status("Verschlüsselung abgeschlossen")
            messagebox.showinfo(
                "Fertig",
                f"Die Datei wurde verschlüsselt:\n\n{output_path}\n\n"
                f"SHA-256 Original:\n{source_hash}\n\n"
                f"SHA-256 verschlüsselt:\n{encrypted_hash}"
                + (f"\n\nSicherheitskopie:\n{backup}" if backup else ""),
            )

        self.run_background(
            task, finished, "Datei verschlüsselt", source, determinate=True
        )

    def decrypt_selected(self) -> None:
        if self.selected_file is None:
            messagebox.showwarning(
                "Keine Datei",
                "Wähle zuerst eine .enc-Datei aus.",
            )
            return
        if self.selected_file.is_dir():
            self.decrypt_selected_folder(self.selected_file)
            return

        if self.selected_file.suffix == ".enc":
            suggested_name = self.selected_file.stem
        else:
            suggested_name = self.selected_file.name + ".dec"

        output = filedialog.asksaveasfilename(
            title="Entschlüsselte Datei speichern",
            initialfile=suggested_name,
            filetypes=[("Alle Dateien", "*.*")],
        )

        if not output:
            return

        output_path = Path(output)
        if not confirm_overwrite(output_path):
            self.set_status("Entschlüsselung abgebrochen")
            return
        password = self.ask_private_key_password("Datei entschlüsseln")
        if password is None:
            return
        source = self.selected_file
        backup_folder = self.backup_folder if self.backup_enabled.get() else None
        if self.backup_enabled.get() and backup_folder is None:
            messagebox.showwarning(
                "Backup-Ordner fehlt", "Bitte zuerst einen Backup-Ordner auswählen."
            )
            return
        self.set_status("Entschlüssele und prüfe Datei im Hintergrund ...")

        def task():
            self.report_progress(0, 3, "Sicherheitskopie")
            backup = create_backup(source, backup_folder) if backup_folder else None
            self.report_progress(1, 3, "Datei wird entschlüsselt")
            decrypt_file(
                source,
                self.private_key,
                output_path,
                passphrase=password or None,
                confirm=False,
            )
            self.report_progress(2, 3, "Ergebnis wird geprüft")
            result = backup, sha256_file(output_path)
            self.report_progress(3, 3, "Fertig")
            return result

        def finished(result) -> None:
            backup, restored_hash = result
            self.set_status("Entschlüsselung abgeschlossen")
            messagebox.showinfo(
                "Fertig",
                f"✓ Datei entschlüsselt und Integrität geprüft:\n\n{output_path}\n\n"
                f"SHA-256 wiederhergestellt:\n{restored_hash}"
                + (f"\n\nSicherheitskopie:\n{backup}" if backup else ""),
            )

        self.run_background(
            task, finished, "Datei entschlüsselt", source, determinate=True
        )

    def ransomware_help(self) -> None:
        source = self.selected_file
        if source is None:
            selected = filedialog.askopenfilename(
                title="Verdächtige verschlüsselte Datei auswählen"
            )
            if not selected:
                return
            source = Path(selected)
            self.set_selected_file(source)

        self.set_status("Analysiere Auswahl im Hintergrund ...")

        def finished(result) -> None:
            report, indicators = result
            self.show_diagnosis(report)
            if not indicators:
                self.scan_result.configure(
                    text=(
                        "✓ KEINE TYPISCHEN RANSOMWARE-HINWEISE GEFUNDEN\n"
                        "Du bist zurück im CryptoTool."
                    ),
                    text_color="#22c55e",
                    fg_color="#052e16",
                    height=64,
                )
                self.set_status("Prüfung abgeschlossen – keine typischen Hinweise")
                messagebox.showinfo(
                    "Keine typischen Hinweise",
                    "Die vollständige Auswahl wurde geprüft. Es wurden keine "
                    "typischen Ransomware-Hinweise gefunden.\n\n"
                    "Das ist keine Garantie; bei einem echten Verdacht sollte "
                    "der Rechner trotzdem professionell geprüft werden.",
                )
                return

            self.scan_result.configure(
                text="⚠ MÖGLICHE RANSOMWARE-HINWEISE GEFUNDEN",
                text_color="#fdba74",
                fg_color="#431407",
                height=54,
            )
            output = filedialog.asksaveasfilename(
                title="Diagnosebericht speichern",
                initialfile=f"{source.name}.diagnose.txt",
                defaultextension=".txt",
                filetypes=[("Textdateien", "*.txt"), ("Alle Dateien", "*.*")],
            )
            if not output:
                self.set_status("Hinweise gefunden – Bericht nicht gespeichert")
                return
            try:
                report_path = Path(output)
                if report_path.resolve() == source.resolve():
                    raise ValueError(
                        "Der Diagnosebericht darf die untersuchte Datei nicht überschreiben."
                    )
                report_path.parent.mkdir(parents=True, exist_ok=True)
                report_path.write_text(report, encoding="utf-8")
            except Exception as error:
                self.set_status("Fehler")
                messagebox.showerror("Fehler", str(error))
                return
            if "CryptoTool-Datei (CT01)" in report:
                suggested_tool = "CryptoTool mit dem passenden priv.key"
            else:
                suggested_tool = "No More Ransom – Crypto Sheriff"
            self.set_status("Ransomware-Diagnose abgeschlossen")
            messagebox.showinfo(
                "Diagnose abgeschlossen",
                "Die Datei wurde nur gelesen und nicht verändert.\n\n"
                f"Empfohlenes Werkzeug:\n{suggested_tool}\n\n"
                f"Bericht:\n{report_path}\n\n"
                "Wichtig: Diese Analyse kann keinen geheimen "
                "Ransomware-Schlüssel berechnen.",
            )

        self.run_background(
            lambda: analyze_target(source, self.report_progress),
            finished,
            "Ransomware-Diagnose",
            source,
            determinate=True,
        )


if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()
