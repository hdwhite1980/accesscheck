# Shipping AccessCheck as an installable Windows app

Two routes. Start with the portable one to confirm the published build runs, then move
to MSIX when you want a real install, Programs & Features entry, and Intune deployment.

---

## Route A - portable (no certificate, 2 minutes)

```powershell
.\dist\build-portable.ps1
```

Publishes a self-contained build to `%LOCALAPPDATA%\Programs\AccessCheck` and creates a
Start-menu shortcut with the app icon. No .NET runtime needed on the machine.

SmartScreen warns on first launch because the exe is unsigned - expected, and the same
thing Gatekeeper did before you notarized the Mac build. Use this to verify the Release
build behaves like the debug one before spending time on signing.

---

## Route B - MSIX (the real installer)

### 1. Prerequisites

First, check what you already have - Visual Studio ships the SDK, so these tools are
often present already:

```powershell
.\dist\check-prereqs.ps1
```

If `makeappx.exe` and `signtool.exe` are missing, install the Windows SDK. The plain
`Microsoft.WindowsSDK` winget id was retired in favour of versioned ones:

```powershell
winget search "Windows SDK"
winget install Microsoft.WindowsSDK.10.0.26100     # or another listed version
```

Alternatives if winget is uncooperative:

* **Visual Studio Installer** -> Modify -> Individual components -> tick
  *Windows 11 SDK (any version)*
* **Direct download** from <https://developer.microsoft.com/windows/downloads/windows-sdk/> -
  during install untick everything except *Windows SDK Signing Tools for Desktop Apps*,
  which keeps it small.

### 2. A signing certificate

MSIX will not install unsigned. Two options:

**Internal / lab** - self-signed:

```powershell
.\dist\new-selfsigned-cert.ps1
```

Prints a thumbprint and exports `AccessCheck-signing.cer`. Every machine that installs
the package must trust that certificate:

```powershell
# ELEVATED PowerShell, on each target machine
.\dist\trust-cert.ps1
```

A self-signed certificate is its **own root**, so it must go into **two** stores:

| Store | Why |
|---|---|
| `LocalMachine\Root` | Makes the certificate chain valid. Without it the install fails with `0x800B010A` - "terminated in a root certificate which is not trusted". |
| `LocalMachine\TrustedPeople` | Authorises the publisher to sideload packages. |

`trust-cert.ps1` handles both and then proves the chain builds rather than assuming it.
A CA-issued certificate needs neither store, because its root already ships in Windows -
which is the main practical reason to buy one.

If the Install button is still greyed out:

```powershell
.\dist\check-package-trust.ps1
```

It reads the signature off the package, reports which stores hold the certificate,
builds the chain, and checks whether sideloading is disabled by policy.

**Production** - buy an OV or EV code-signing certificate. Same decision you made for
the Mac build with a Developer ID: a real certificate removes the trust-provisioning
step entirely and satisfies SmartScreen. Install it into `Cert:\CurrentUser\My` and use
its thumbprint below.

### 3. Build and sign

```powershell
.\dist\build-msix.ps1 -CertThumbprint <thumbprint> -Version 0.1.0.0
```

The script publishes, stages the manifest and assets, **rewrites `Publisher` in the
manifest from the certificate's subject**, packs, signs, and verifies. That rewrite
matters: Windows compares those two strings byte for byte and refuses the install on any
mismatch, which is the single most common MSIX packaging failure.

Output: `dist\out\AccessCheck-<version>.msix`

### 4. Install

```powershell
.\dist\install-local.ps1
```

Removes any previous version and installs the newest package. Afterwards AccessCheck
appears in the Start menu and in Settings -> Apps like any other installed application.

---

## Deploying through Intune

1. Download the **Microsoft Win32 Content Prep Tool** only if you use the `.intunewin`
   route - MSIX does not need it. Intune supports MSIX directly as a *Line-of-business
   app*.
2. Intune admin center -> **Apps -> Windows -> Add -> Line-of-business app**.
3. Upload `AccessCheck-<version>.msix`. Intune reads the identity, version, and
   publisher from the package.
4. Assign to a group.

Two things to get right:

- **Certificate trust.** If the package is self-signed, deploy the `.cer` to
  `Trusted People` first - a separate Intune configuration profile, or a script. With a
  purchased certificate this step disappears.
- **Per-user install.** MSIX installs per user by default, which suits this app: its
  data lives in `%APPDATA%\AccessCheck` and its credentials are DPAPI-bound to the
  signed-in user anyway. Assign to users, not devices.

---

## Versioning

Three places carry a version; keep them aligned:

| Where | Format | Purpose |
|---|---|---|
| `src\AccessCheck.App\AccessCheck.App.csproj` | `0.1.0` | Shown in the app header |
| `dist\AppxManifest.xml` | `0.1.0.0` | Package identity |
| `build-msix.ps1 -Version` | `0.1.0.0` | Overrides the manifest at build time |

MSIX requires four parts and **refuses to install a package whose version is not higher
than the installed one** - so bump before every rebuild you intend to distribute, or the
install will silently keep the old binary. The app header shows the running version and
tags `(MSIX)` when it is packaged, so a stale install is obvious rather than mysterious.

---

## What the app writes at runtime

Everything lives under `%APPDATA%\AccessCheck`:

- `appsettings.json` - tenant, client id, AI endpoint (no secrets)
- `catalog.json`, `groups.json` - synced tenant data
- `history.jsonl` - the audit trail
- `prompt-log.txt`, `ps-script-log.txt` - verbatim prompts and PowerShell scripts
- `secrets\` - DPAPI-encrypted API key and token cache

Nothing is written to the install directory, which is what lets MSIX work at all, and
what makes settings survive an uninstall/reinstall cycle.

---

## Optional: PowerShell for Exchange and Purview

Those features shell out to PowerShell. Windows PowerShell 5.1 works; PowerShell 7 is
better:

```powershell
winget install Microsoft.PowerShell
pwsh -c "Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force"
```

Everything else in the app works without it.
