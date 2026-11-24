# ⚡ WinPulse — Explainable Windows Service & Deep Startup Optimizer

> **Stop guessing which `svchost.exe` is eating your RAM.**  
> WinPulse is a zero-dependency, native Windows GUI tool (pure PowerShell + WPF) that shows you **how much live RAM** unnecessary Windows services and hidden startup tasks are consuming, **what breaks if you disable them**, and lets you reclaim memory with **1-click JSON rollback**.

---

## 🤔 "Why can't I just use Windows Task Manager?"

This is the #1 question people ask on Reddit and Hacker News. Here is why Windows Task Manager isn't enough:

| Feature | Windows Task Manager (`taskmgr.exe`) | ⚡ **WinPulse** |
| :--- | :--- | :--- |
| **Per-Service RAM Usage** | ❌ **Hidden.** The *Services* tab shows zero memory columns, and the *Processes* tab groups dozens of services into cryptic `Service Host (svchost.exe)` buckets. | ✅ **Exact PID & RAM Mapping.** Maps every service via WMI/CIM to its hosting `svchost.exe` PID and shows its exact live RAM footprint in MB. |
| **"What Breaks If I Disable It?"** | ❌ **Zero guidance.** Lists 250+ cryptic names (`DiagTrack`, `PcaSvc`, `SysMain`, `WbioSrvc`) without telling you if disabling one breaks Xbox Game Pass, printers, or nothing at all. | ✅ **Explainable Impact Cards.** Curated database splits services into **Safe (Telemetry/Bloat)** vs **Optional (Feature-specific)** and tells you in plain English what breaks before you click. |
| **Permanent Service Disable** | ❌ **Resets on Reboot.** Right-clicking *Stop* in Task Manager only stops the service for the current session; Windows restarts it on the next boot. | ✅ **Stops Now & Disables on Boot.** Stops the active process immediately *and* switches its startup mode to `Disabled`. |
| **Hidden Startup Scheduled Tasks** | ❌ **Blind to Task Scheduler.** Task Manager's *Startup Apps* tab only checks Registry `Run` keys and Startup folders. It completely misses **Task Scheduler logon tasks** where Chrome, Edge, Adobe Creative Cloud, and OEM updaters hide. | ✅ **Deep 3-Vector Startup Scan.** Scans `HKCU`/`HKLM` Registry Run keys, User & Common Startup Folders, **and** non-Microsoft Logon/Boot Scheduled Tasks in one table. |
| **1-Click Undo / Rollback** | ❌ **No Undo.** If you disable 15 items and forget which ones were set to `Automatic` vs `Manual`, you have to fix them one by one in `services.msc`. | ✅ **Automatic JSON Snapshots.** Every optimization automatically saves a timestamped state backup in `./backups/` that can be restored in one click. |

---

## 🚀 Quick Start (Zero Dependencies)

WinPulse uses native Windows PowerShell and WPF (`.NET PresentationFramework`), which is pre-installed on every Windows 10 and Windows 11 PC.

### Option 1: Double-Click Launcher (Recommended)
1. Clone or [Download the ZIP](https://github.com/nareshbabuk7/Windows_Optimizer/archive/refs/heads/main.zip) from [`nareshbabuk7/Windows_Optimizer`](https://github.com/nareshbabuk7/Windows_Optimizer):
   ```bash
   git clone https://github.com/nareshbabuk7/Windows_Optimizer.git
   cd Windows_Optimizer
   ```
2. Double-click **[`Launch-WinPulse.bat`](Launch-WinPulse.bat)**.
3. Approve the Administrator UAC prompt so WinPulse can stop system-level services.

### Option 2: PowerShell Terminal
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\WinPulse.ps1
```

---

## 🛡️ Safety Tiers

WinPulse never disables critical OS services (like Windows Defender, Audio, DHCP, DNS, or Windows Update). Every scanned item is categorized into clear tiers:

- 🟢 **`Safe` (Pre-selected by default)**: Background telemetry, diagnostics, legacy enterprise daemons, retail store demo mode, and redundant auto-updaters (`DiagTrack`, `WerSvc`, `RetailDemo`, `Fax`, `RemoteRegistry`, `MapsBroker`, etc.).
- 🟡 **`Optional` (Unchecked by default — User choice)**: Legitimate Windows subsystems that consume 20–150 MB of RAM even when you don't own or use the hardware:
  - **Print Spooler (`Spooler`)**: Free ~20–40 MB RAM if you never print.
  - **SysMain (`Superfetch`) & Windows Search Indexer (`WSearch`)**: Free ~100–250 MB RAM and background SSD disk I/O on modern NVMe systems.
  - **Xbox Live Services (`XblAuthManager`, `XblGameSave`, etc.)**: Safe to disable if you only play on Steam/Epic.
  - **Bluetooth & Biometrics (`bthserv`, `WbioSrvc`)**: Safe to disable on desktop PCs without Bluetooth or fingerprint sensors.
  - **Hyper-V Guest Daemons (`vmic*`)**: Safe to disable on bare-metal PCs not using Hyper-V VMs.

---

## 🤝 Contributing New Rules

All service definitions and startup patterns live in a single human-readable JSON file: **[`data/rules.json`](data/rules.json)**.
Want to add an OEM bloatware service (ASUS Armoury Crate, Razer Synapse, HP Touchpoint Analytics, Dell SupportAssist)? Open a PR adding an entry to `data/rules.json` with:
- `name` & `displayName`
- `tier` (`Safe` or `Optional`)
- `description` (what it actually does)
- `impact` (what breaks if disabled)

---

## 📄 License

Distributed under the [MIT License](LICENSE).
