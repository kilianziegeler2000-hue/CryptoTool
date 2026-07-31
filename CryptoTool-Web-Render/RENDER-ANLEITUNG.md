# CryptoTool auf Render veröffentlichen

Diese Variante ist für einen Render Web Service vorbereitet.

## Veröffentlichung

1. Entpacke die ZIP-Datei.
2. Lade den Inhalt in ein neues GitHub-Repository hoch.
3. Öffne Render und wähle **New > Blueprint**.
4. Verbinde das GitHub-Repository.
5. Render erkennt `render.yaml` und richtet den Web Service ein.
6. Starte die Veröffentlichung.

Alternativ kannst du einen normalen **Web Service** anlegen:

- Runtime: `Node`
- Build Command: `npm ci && npm run build`
- Start Command: `npm start`
- Health Check Path: `/`

## Google-Anmeldung

Die bisherige ChatGPT-Anmeldung wurde aus dieser Render-Version entfernt.
Eine echte Google-Anmeldung wird ergänzt, sobald eine eigene Domain und ein
Google-OAuth-Webclient vorhanden sind. Speichere Client-Secrets ausschließlich
als geheime Environment Variables in Render und niemals im Quellcode.

## Datenschutz

Ver- und Entschlüsselung sowie die Ransomware-Hinweisprüfung laufen lokal im
Browser. Die ausgewählten Dateien werden nicht an Render übertragen.
