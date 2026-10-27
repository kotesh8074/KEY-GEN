# Offline license setup

## Create the signing key once

From the project folder, run:

```powershell
node backend/scripts/generate-license-keys.mjs
```

This saves the public verification key in `.env.local` and the private signing key in `backend/license-private-key.txt`. Keep that private key secret and backed up securely. Build the installer after creating/updating the key pair so the app includes its matching public key.

## Generate an offline activation or renewal key

The graphical generator collects the recipient/person or organization, optional contact, computer ID, issue type (new or renewal), and key duration. Choose 1 day, 3 months, 6 months, yearly, or a custom number of days; the expiry date is calculated automatically. It displays and can copy the signed key and a summary containing the recipient, device ID, license ID, local generation time, issue type, and expiry.

To open the generator entirely offline from the project folder in PowerShell:

```powershell
$env:LICENSE_ADMIN_TOKEN = Read-Host "Set a temporary local generator password"
node backend/server.mjs
```

Then open `http://127.0.0.1:3000/` in the browser and enter the temporary password. The local server binds to loopback only, reads the signing key from `backend/license-private-key.txt`, and does not require an internet service or database. Keep the signing key private.

## Host the generator online

The generator page is a single HTML file, but signed keys must be created by the Node.js backend so the private signing key is never sent to the browser. Deploy the `backend` folder to a Node.js 20+ host and use `npm start` as the start command. Configure these environment variables in the host's secret settings:

- `NODE_ENV=production` (the server then listens on `0.0.0.0`; or set `HOST=0.0.0.0` explicitly)
- `LICENSE_ADMIN_TOKEN` = a strong, unique admin password
- `LICENSE_PRIVATE_KEY_BASE64` = the contents of `backend/license-private-key.txt`

Use the host's HTTPS URL to open the generator. Do not put the private key or admin password in the HTML, source control, or a public static-site host. Keep access restricted to trusted administrators; anyone with the admin password can issue licenses.

Alternatively, replace the device ID and expiry in this command:

```powershell
node backend/scripts/create-offline-license.mjs <device-id> <YYYY-MM-DD> [issued-to] [contact] [new|renewal]
```

Copy the printed `LAB1-...` key and provide it to the user. The key is signed, expires on the selected date, and is bound to that device ID. The user pastes it into the app for activation or Settings for renewal; neither action requires internet. Previously issued signed `LAB1-` keys remain valid.

To build the Windows installer:

```powershell
npm run dist:win
```

Changing the computer's clock can affect offline expiry checks.

## Windows installer security

- The installer must be signed with your organization's trusted Windows code-signing certificate to show a verified publisher. Keep the PFX file and password private; configure them as `CSC_LINK` and `CSC_KEY_PASSWORD` environment variables on the build machine before running `npm run dist:win`.
- Without a trusted certificate, Windows may show an unknown-publisher or SmartScreen warning. Signing reduces publisher warnings but cannot guarantee that every antivirus product will never report a false positive.
- Do not ask users to disable antivirus. Scan the generated installer with Microsoft Defender and submit any suspected false positive to the antivirus vendor for review.

## Automatic local backups

The installed desktop app creates an `Auto Backup` folder under the current Windows user's AppData directory by default. In **Backup & Database Utilities**, choose every minute, daily (default), weekly, or monthly; choose another writable folder if needed; or create a backup immediately. Scheduled backups run while the app is open and the newest 30 automatic backups are retained.

## Account recovery

The sign-in page's **Forgot password?** flow accepts the account username or email and an internal local recovery key. The key is stored internally with the app database and is intentionally not displayed or editable in Settings. The same settings section lets the signed-in administrator change their username, display name, and password; copy the device ID; view license issue details; and renew with a signed offline key before expiry.
