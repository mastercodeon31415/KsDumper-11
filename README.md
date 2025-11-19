# KsDumper-11
https://github.com/user-attachments/assets/7558d492-859a-429b-b51e-285cae623c91

## Whats new v1.3.5H (Hotfix)
+ **Fixed In-Memory .NET Dumping**: Addressed a critical logic flaw where .NET assemblies loaded via `Assembly.Load(byte[])` (Flat/Raw memory map) were being read from incorrect offsets, resulting in empty method bodies.
+ **Fixed Decompilation Offsets**: Adjusted the PE Header Generator to use Standard Alignment (0x2000 Section / 0x200 File). This ensures RVA-to-FileOffset calculations are correct, allowing tools like **dnSpy** to map code correctly (e.g., fixing the 0x2050 vs 0x250 offset mismatch).
+ **Fixed PE Header Corruption**: Resolved a bug in the Section Header writing logic that caused file structure corruption if section names were shorter than 8 bytes.
+ **Result**: In-memory modules (often used by packers/loaders) now dump with valid headers, correct code content, and are fully decompilable.

## Whats new v1.3.5
+ **Manual Map Detection**: The driver now utilizes VAD-style memory scanning to detect executable memory regions not linked in the system loader. These appear as **Red** entries in the Module View.
+ **.NET & Architecture Detection**: Automatically detects if a process is running the .NET Runtime (CLR) and identifies the specific architecture. These processes appear as **Cyan** in the process list.
+ **Enhanced IAT Reconstruction**: Completely rewrote the Import Address Table reconstruction engine. It now parses exports directly from **memory** rather than disk. This allows for resolving imports from Manually Mapped DLLs and fixes version mismatch issues.
+ **Module Dumping**: You can now dump specific DLLs (including hidden manual maps) via the Module View.
+ **Driver Stability**: Fixed a critical Bad Pool Caller (0xC2) BSOD by implementing safe memory allocation tags and buffer resizing logic in the kernel.
+ **UI Updates**: Added columns for "Framework" (.NET/Native) in the main list and color-coding for special modules.
+ **KDU Version Update**: Updated KDU from v1.4.1 to v1.4.4. Three new providers have been added.

## Whats new v1.3.4
+ Added new feature Anti Anti Debugging Tools Detection
    + Randomized MainWindow Title, most Control Titles, and the exe file name during runtime
    + The process name is reverted to KsDumper11.exe upon program closing
    + Enable Anti Anti Debugging Tools Detection check box setting added
    + This feature was added in hopes to make KsDumper 11 more stealthy when trying to dump programs that have more rudimentary Anti Debugging techniques implemented
+ Lots of source code cleanup
+ Fixed Easter Egg window that would not close upon clicking of the close button
+ Changed all labels in every form to be manually drawn to get around label text being changed when Anti Anti Debugging Tools Detection feature is enabled
+ Migrated from Application Settings to custom Settings.json for saving and loading of settings

## Whats new v1.3.3
+ Updated KDU to v1.4.1
	New providers were added, see KDU patch notes on latest release.

## Whats new v1.3.2
+ Provider selction window now has a button to reset or wipe provider settings.
	This means that all the providers will be reset to needing to be tested, and the default provider will be reset.
+ Fixed a bug in the provider selection window that would prevent it from being closed when opened from the main Dumper window.
![image](https://github.com/user-attachments/assets/c9f3fd50-4438-4b96-beba-e5fbd82108e1)

## Whats new v1.3.1
+ Updated KDU to v1.4.0! Provider count is now 44

## Whats new v1.3
+ Updated KDU to KDU V1.3.4! Over 40 different providers are now available!
+ Removed the old auto detection of working providers and replaced it with a new provider selector. Users can now select which provider they want to use to load the driver. As well as test providers to see if they work on your system!
+ Testing some Providers may BSOD crash the system, KsDumper now has support for being ran again after a crash and will mark the last checked provider as non-working!
+ Anytime kdu loads and it detects a saved providers list, it will try to load the KsDumper driver using the default provider
+ Providers list and selected default provider are now saved as JSON files!
+ Updated to .NET Framework v4.8

![KsDumper v1.3 Provider Selector window](https://github.com/user-attachments/assets/391bcbf0-4255-4c7a-8cd9-3abb08da34f0)

## Whats new v1.2
+ KsDumper will now try and start the driver using the default kdu exploit provider #1 (RTCore64.sys)
+ If the default provider does not work, KsDumper will scan all kdu providers and save each one that works into a list.
+ Anytime kdu loads and it detects a saved providers list, it will try to load the KsDumper driver using each saved provider until one works.
+ This technique should increase the amount of systems that the driver will be able to be loaded on. 

## Discord / Support
You can join the official KsDumper 11 discord server where I will be managing ongoing issues. 
For those of you who find that ksDumper won't start on their system, please join the server and post your logs in the support channel. 
Please keep in mind that until others volunteer to help in development of this tool, I am only one person with a finite amount of knowledge. 
I'm always open to feedback and suggestions!
https://discord.gg/HFye2Kac

## Features
- **Kernel-Mode Dumping**: Reads memory directly using `MmCopyVirtualMemory`, bypassing user-mode hooks.
- **IAT Reconstruction**: Automatically repairs the Import Address Table using in-memory export parsing. Makes dumps executable!
- **Manual Map Detection**: Identifies executable memory regions hidden from the system loader.
- **.NET Support**: Detects CLR usage and specific architectures (x86/x64/AnyCpu).
- **KDU Integration**: Selection of working kdu exploit providers to load unsigned drivers.
- **Process Management**: Suspend, Resume, Kill processes from kernel.
- **Module Enumeration**: View and dump specific DLLs (including hidden ones).
- **Anti-Anti-Debug**: Randomized window titles and stealthy UI drawing.
- **Driver Unload**: Option to unload the kernel driver on exit.
- **PE Reconstruction**: Rebuilds PE32/PE64 headers and sections.
- Works on protected system processes & processes with stripped handles (anti-cheats).
- Works on Windows 11.
![Canary Channel Insider Build Win 11 Ksdumper](https://github.com/user-attachments/assets/8c386012-5cbe-43b6-8dc4-8de5e74f48d7)

## Usage Guide

### Prerequisites
1.  **x64 Windows OS** (The driver is 64-bit only).
2.  **Secure Boot Disabled** (Required for most KDU providers).
3.  **Administrator Privileges** (Required to load drivers).

### Initial Setup (First Run)
The old way of loading the driver (capcom exploit) is patched in Windows 11. This version uses KDU.
1.  Run `KsDumper11.exe` as Administrator.
2.  The **Provider Selector** window will appear.
3.  Select a provider from the list (Provider #1 usually works for most).
4.  Click **Test Driver**. If "Driver Loaded!" appears in Green, click **Set Default Provider**.
5.  The main dumper window will open.

### Dumping a Process
1.  Locate your target process in the list.
    *   **Cyan Text**: Indicates a .NET process.
    *   **White Text**: Indicates a Native process.
2.  Right-click the process and select **Dump Process**.
3.  Check the logs at the bottom. You should see:
    *   "Getting Module List for IAT Reconstruction..."
    *   "IAT Reconstructed and New Section Added."
4.  Save the file when prompted. The dump should be runnable.

### Analyzing & Dumping Modules (Manual Maps)
1.  Select a process in the list.
2.  Right-click and select **View Modules**.
3.  A new window will appear listing all loaded code:
    *   **Red Text**: Manually Mapped regions (Hidden from normal tools).
    *   **Cyan Text**: .NET Runtime modules.
4.  Right-click any module (especially Red ones) and select **Dump Module** to save it to disk for analysis.

## Building the Project
If you wish to compile KsDumper 11 yourself, follow these steps carefully.

### Requirements
*   **Visual Studio 2019** with **WDK (Windows Driver Kit)** installed (Required for the Driver).
*   **Visual Studio 2022** (Required for the Client App).
*   **.NET Framework 4.8**.

### Steps
1.  **Build the Driver**:
    *   Open `Driver\KsDumperDriver.sln` in **VS 2019**.
    *   Select configuration **Release / x64**.
    *   Build the solution. This produces `KsDumperDriver.sys`.
2.  **Update Resources**:
    *   Open `KsDumper11.sln` in **VS 2022**.
    *   Go to `Project Properties -> Resources`.
    *   Remove the old `KsDumperDriver` resource.
    *   Add the new `KsDumperDriver.sys` you just built as a file resource and name it `KsDumperDriver`.
3.  **Build the Client**:
    *   Select configuration **Release / Any CPU** (or x64).
    *   Build the solution.
    *   The output folder will contain `KsDumper11.exe`. On the first run, it will extract `kdu.exe` and the driver automatically.

## Known Issues and Limitations
*   **Driver Unload Stability**: Unloading the driver relies on `ZwUnloadDriver`. If the KDU exploit left the kernel in an unstable state, unloading may fail or cause a BSOD.
*   **Advanced Obfuscation**: While IAT reconstruction is robust, heavily virtualized packers (like VMProtect with import emulation) may still require manual fixups in a debugger.
*   **Antivirus**: Because this tool exploits a vulnerable driver to load an unsigned rootkit, almost every Antivirus will flag `kdu.exe` or `KsDumperDriver.sys`. You must add an exclusion.

## Disclaimer
The new kdu provider selector can and WILL crash windows if a bad provider is tested. As such, I have implimented functionality to allow KsDumper to be ran again after a crash, and it will mark the last tested provider as non-working. This way, users will be prevented from testing that provider again and less crashes should result from general usage of KsDumper 11.
Please do beware that it can sometimes crash the OS even still. I do not take any responsibility for any damage that may occur to your system from using this tool.

Due to the nature of how KDU works to map the kernel driver, it is unknown if the system you run this on 
will have a exploitable driver according to kdu providers.
If you try to boot KsDumper 11 and it fails to start the driver, trying again as administrator.
If it still fails post the log. There is a manualloader.bat you can try as well to see the output directly.
You MUST run KsDumper at least once for the kdu.exe file and its dlls to be self extracted for the ManualLoader.bat to work.

This project has been made available for informational and educational purposes only.
Considering the nature of this project, it is highly recommended to run it in a `Virtual Environment`. I am not responsible for any crash or damage that could happen to your system.

**Important**: This tool makes no attempt at hiding itself. If you target protected games, the anti-cheat might flag this as a cheat and ban you after a while. Use a `Virtual Environment` !

## Contributing

Contributions are welcome! If you have suggestions for improvements or encounter any issues, please feel free to open an issue or submit a pull request.

## Donation links

Anything is super helpful! Anything donated helps me keep developing this program and others!
- https://www.paypal.com/paypalme/lifeline42
- https://cash.app/$codoen314
- BTC: bc1qp8pay5qrg77kg2yyguvlwjxpnl8u0wl4r8hddp

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/mastercodeon31415/KsDumper-11/blob/main/LICENSE) file for details. 

## References
- https://github.com/EquiFox/KsDumper
- https://github.com/hfiref0x/KDU
- https://github.com/not-wlan/drvmap
- https://github.com/Zer0Mem0ry/KernelBhop
- https://github.com/NtQuery/Scylla/
- http://terminus.rewolf.pl/terminus/
- https://www.unknowncheats.me/
