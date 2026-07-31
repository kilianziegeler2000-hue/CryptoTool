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

Die echte Google-Anmeldung ist eingebaut. Trage in der Google Cloud Console
bei deinem OAuth-Webclient Folgendes ein:

- Authorized JavaScript origin:
  `https://cryptotool-bn4f.onrender.com`
- Authorized redirect URI:
  `https://cryptotool-bn4f.onrender.com/api/auth/callback/google`

Trage anschließend bei Render unter **Environment** diese Variablen ein:

- `GOOGLE_CLIENT_ID` – deine öffentliche Client-ID
- `GOOGLE_CLIENT_SECRET` – dein geheimer Clientschlüssel
- `AUTH_SECRET` – über **Generate** einen langen Zufallswert erstellen

Speichere Client-Secrets ausschließlich als geheime Environment Variables in
Render und niemals im Quellcode oder auf GitHub. Führe nach Änderungen einen
neuen Deploy aus.

## Datenschutz

Ver- und Entschlüsselung sowie die Ransomware-Hinweisprüfung laufen lokal im
Browser. Die ausgewählten Dateien werden nicht an Render übertragen.
