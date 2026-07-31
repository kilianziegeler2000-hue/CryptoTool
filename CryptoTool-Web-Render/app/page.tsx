"use client";

import { useMemo, useRef, useState } from "react";

type Mode = "encrypt" | "decrypt" | "scan";
type ScanResult = { name: string; status: "safe" | "warning"; detail: string };

const suspiciousExtensions = [
  ".locked", ".encrypted", ".crypted", ".crypt", ".lockbit", ".ryuk", ".wncry",
];
const ransomNotes = [
  "decrypt.txt", "decrypt_files.txt", "how_to_decrypt.txt",
  "how_to_restore_files.txt", "restore_files.txt", "ransom_note.txt",
];
const encoder = new TextEncoder();

function concatBytes(...parts: Uint8Array[]) {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}

async function deriveKey(password: string, salt: Uint8Array) {
  const material = await crypto.subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt as BufferSource, iterations: 250_000, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function download(data: BlobPart, name: string) {
  const url = URL.createObjectURL(new Blob([data], { type: "application/octet-stream" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  URL.revokeObjectURL(url);
}

export default function Home() {
  const [mode, setMode] = useState<Mode>("encrypt");
  const [files, setFiles] = useState<File[]>([]);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("Bereit");
  const [results, setResults] = useState<ScanResult[]>([]);
  const fileInput = useRef<HTMLInputElement>(null);
  const folderInput = useRef<HTMLInputElement>(null);

  const selectedText = useMemo(() => {
    if (!files.length) return "Noch nichts ausgewählt";
    if (files.length === 1) return files[0].name;
    return `${files.length} Dateien ausgewählt`;
  }, [files]);

  function selectMode(nextMode: Mode) {
    setMode(nextMode); setFiles([]); setResults([]); setMessage("Bereit");
  }

  function accept(list: FileList | null) {
    if (!list) return;
    setFiles(Array.from(list)); setResults([]); setMessage(`${list.length} Datei(en) geladen`);
  }

  async function encryptFile() {
    if (files.length !== 1 || password.length < 8) {
      setMessage("Bitte eine Datei und ein Passwort mit mindestens 8 Zeichen wählen."); return;
    }
    setBusy(true);
    try {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const key = await deriveKey(password, salt);
      const encrypted = new Uint8Array(await crypto.subtle.encrypt(
        { name: "AES-GCM", iv }, key, await files[0].arrayBuffer(),
      ));
      download(concatBytes(encoder.encode("CTWEB01"), salt, iv, encrypted), `${files[0].name}.ctweb`);
      setMessage("✓ Datei lokal verschlüsselt und heruntergeladen.");
    } catch { setMessage("Verschlüsselung fehlgeschlagen."); }
    finally { setBusy(false); }
  }

  async function decryptFile() {
    if (files.length !== 1 || !password) {
      setMessage("Bitte eine .ctweb-Datei und das richtige Passwort wählen."); return;
    }
    setBusy(true);
    try {
      const bytes = new Uint8Array(await files[0].arrayBuffer());
      if (new TextDecoder().decode(bytes.slice(0, 7)) !== "CTWEB01") throw new Error();
      const salt = bytes.slice(7, 23); const iv = bytes.slice(23, 35); const payload = bytes.slice(35);
      const key = await deriveKey(password, salt);
      const clear = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, payload);
      const name = files[0].name.endsWith(".ctweb") ? files[0].name.slice(0, -6) : `${files[0].name}.dec`;
      download(clear, name); setMessage("✓ Datei entschlüsselt und Integrität bestätigt.");
    } catch { setMessage("Entschlüsselung fehlgeschlagen: Passwort oder Datei ist falsch."); }
    finally { setBusy(false); }
  }

  async function scanFiles() {
    if (!files.length) { setMessage("Bitte zuerst eine Datei oder einen Ordner auswählen."); return; }
    setBusy(true);
    const next = files.map((file) => {
      const lower = file.name.toLowerCase();
      const extension = suspiciousExtensions.find((suffix) => lower.endsWith(suffix));
      const note = ransomNotes.includes(lower.split("/").pop() || lower);
      if (extension || note) return {
        name: file.webkitRelativePath || file.name,
        status: "warning" as const,
        detail: note ? "Mögliche Lösegeldnotiz" : `Verdächtige Endung ${extension}`,
      };
      return { name: file.webkitRelativePath || file.name, status: "safe" as const, detail: "Keine typischen Hinweise" };
    });
    setResults(next); setBusy(false);
    const warnings = next.filter((item) => item.status === "warning").length;
    setMessage(warnings ? `⚠ ${warnings} mögliche Hinweise gefunden.` : "✓ Keine typischen Ransomware-Hinweise gefunden.");
  }

  const action = mode === "encrypt" ? encryptFile : mode === "decrypt" ? decryptFile : scanFiles;

  return (
    <main>
      <nav>
        <div className="brand"><span>◆</span> CryptoTool</div>
        <div className="nav-actions">
          <div className="offline">● 100 % lokal & offline</div>
          <a className="download-button" href="/CryptoTool-Desktop.zip" download>↓ Download</a>
        </div>
      </nav>
      <section className="hero">
        <div className="eyebrow">AES-256-GCM · PRIVATE BY DESIGN</div>
        <h1>Deine Dateien.<br /><em>Deine Kontrolle.</em></h1>
        <p>Verschlüsseln, entschlüsseln und auf typische Ransomware-Hinweise prüfen – direkt in deinem Browser. Keine Datei verlässt dein Gerät.</p>
      </section>

      <section className="tool-card">
        <div className="tabs">
          <button className={mode === "encrypt" ? "active" : ""} onClick={() => selectMode("encrypt")}>🔒 Verschlüsseln</button>
          <button className={mode === "decrypt" ? "active" : ""} onClick={() => selectMode("decrypt")}>🔓 Entschlüsseln</button>
          <button className={mode === "scan" ? "active warning" : ""} onClick={() => selectMode("scan")}>◉ Ransomware-Check</button>
        </div>

        <div className="tool-body">
          <div className="tool-copy">
            <span className="step">01 / AUSWAHL</span>
            <h2>{mode === "encrypt" ? "Datei schützen" : mode === "decrypt" ? "Datei wiederherstellen" : "Dateien prüfen"}</h2>
            <p>{mode === "scan" ? "Wähle eine Datei oder einen ganzen Ordner. Wir suchen nach typischen lokalen Hinweisen." : "Wähle eine Datei. Die Verarbeitung findet ausschließlich auf diesem Gerät statt."}</p>
          </div>

          <div className="dropzone" onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); accept(event.dataTransfer.files); }}>
            <div className="drop-icon">⇩</div><strong>{selectedText}</strong><span>Datei hier ablegen oder auswählen</span>
            <div className="picker-row">
              <button onClick={() => fileInput.current?.click()}>Datei auswählen</button>
              {mode === "scan" && <button className="secondary" onClick={() => folderInput.current?.click()}>Ordner auswählen</button>}
            </div>
            <input ref={fileInput} type="file" hidden onChange={(event) => accept(event.target.files)} />
            <input ref={folderInput} type="file" hidden multiple {...({ webkitdirectory: "" } as React.InputHTMLAttributes<HTMLInputElement>)} onChange={(event) => accept(event.target.files)} />
          </div>

          {mode !== "scan" && <label className="password"><span>Passwort</span><input type="password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Mindestens 8 Zeichen" /><small>Das Passwort wird niemals gespeichert oder übertragen.</small></label>}

          <button className="primary-action" disabled={busy} onClick={action}>{busy ? "Wird verarbeitet …" : mode === "encrypt" ? "Jetzt sicher verschlüsseln" : mode === "decrypt" ? "Jetzt entschlüsseln" : "Ransomware-Check starten"}</button>
          <div className={`status ${message.startsWith("⚠") ? "danger" : message.startsWith("✓") ? "success" : ""}`}>{message}</div>

          {results.length > 0 && <div className="results"><div className="result-head"><span>Datei</span><span>Bewertung</span></div>{results.slice(0, 100).map((result, index) => <div className="result-row" key={`${result.name}-${index}`}><span>{result.name}</span><span className={result.status}>{result.detail}</span></div>)}</div>}
        </div>
      </section>

      <section className="trust"><article><b>01</b><h3>Keine Uploads</h3><p>Dateien bleiben vollständig auf deinem Gerät.</p></article><article><b>02</b><h3>Starke Kryptografie</h3><p>AES-256-GCM mit passwortbasierter Schlüsselableitung.</p></article><article><b>03</b><h3>Klare Diagnose</h3><p>Verdächtige Endungen und Lösegeldnotizen werden sichtbar gemacht.</p></article></section>
      <footer><span>CryptoTool Web</span><span>Privat. Lokal. Transparent.</span></footer>
    </main>
  );
}
