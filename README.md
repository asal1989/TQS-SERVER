# TQS ERP — Local Office Server Setup

## What This Is
A local server that stores all bill tracker data in a real database (SQLite).
All office users connect to one central server over your office WiFi.

---

## ⚠️ IMPORTANT — Where to Place This Folder

**Extract the zip and place the `tqs-merged` folder in a simple path like:**
```
C:\TQS-Server\tqs-merged\
```

**Do NOT place it in:**
- `Downloads` folder (Windows may block writes)
- `Desktop` (can cause permission issues)  
- `Program Files` or `Program Files (x86)` (protected by Windows)
- Inside another zip or nested folder (e.g. `tqs-merged\new\tqs-merged\`)
- OneDrive / Google Drive synced folders (causes file lock conflicts)

If you get **"Seed failed: EPERM"** or **"operation not permitted"** — this is the cause.
Move the folder to `C:\TQS-Server\` and restart.

---

## Step 1 — Install Node.js (One time, on server PC only)

1. Go to: https://nodejs.org
2. Download the **LTS** version (e.g. v20.x)
3. Install it (keep all defaults)
4. To verify: open Command Prompt → type `node --version` → should show v20.x

---

## Step 2 — Set Up the Server (One time)

1. Extract the zip file
2. Move the `tqs-merged` folder to `C:\TQS-Server\tqs-merged\`
3. Double-click `START_SERVER.bat`
4. First time only: it will install packages (takes ~30 seconds)
5. You will see something like:
   ```
   Network: http://192.168.1.15:3000
   ```
   **Write down this IP address** — share it with all users.

---

## Step 3 — Seed the Database (One time)

When you first start, the database is empty. You need to import your existing bills:

1. Open the tracker in browser: `http://localhost:3000`
2. Log in as **Admin** (PIN: 0000)
3. Click **"⚡ Seed DB"** button (appears only for Admin)
4. This imports all existing bills into the database
5. Done — data is now in the database!

---

## Step 4 — All Users Connect

Tell all staff to open their browser and go to:
```
http://192.168.1.15:3000
```
(use your actual IP from Step 2)

- Works on Chrome, Firefox, Edge
- Works on Windows, Mac, Android, iPad
- All connected to the same live database
- No app installation needed for users

---

## Daily Use

**Server PC**: Just double-click `START_SERVER.bat` every morning when office starts.
**All users**: Open browser → type the server URL → log in with department PIN.

The server PC must stay ON while others are using the tracker.

---

## File Structure

```
tqs-merged\
├── server.js          <- Main server (don't edit)
├── package.json       <- Node.js config
├── START_SERVER.bat   <- Double-click to start
├── INSTALL_FIRST.bat  <- Run this once if START_SERVER fails
├── tqs_erp.db         <- Database file (auto-created -- BACK THIS UP!)
├── public\
│   └── index.html     <- The tracker app
└── README.md          <- This file
```

---

## Backup

The entire database is in **`tqs_erp.db`**.
Copy this file to a USB drive or Google Drive regularly.

To restore: copy the `.db` file back into the tqs-merged folder and restart.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "Seed failed: EPERM" | Move folder to C:\TQS-Server\tqs-merged\ and restart |
| "operation not permitted" | Folder is in a protected location - see note above |
| "Cannot connect" from other PCs | Check Windows Firewall - allow Node.js on port 3000 |
| Server not starting | Make sure Node.js is installed (node --version) |
| Database errors | Check folder is not inside OneDrive/Google Drive sync |
| Users can't see updates | Press F5 to refresh |

### Allow Node.js through Windows Firewall:
1. Start -> Windows Defender Firewall -> Advanced Settings
2. Inbound Rules -> New Rule -> Port -> TCP -> 3000 -> Allow -> Done

---

## Ports

Default port: **3000**
To change: open `server.js` and edit `const PORT = 3000;`
