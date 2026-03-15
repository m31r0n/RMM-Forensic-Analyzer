"""
Database of known RMM log file locations per OS.

Maps RMM tool names to their default installation and log paths
on Windows, Linux, and macOS.  Environment-variable placeholders
(e.g. %APPDATA%) are expanded at discovery time by the engine.
"""

from __future__ import annotations

# ── Known directory paths ────────────────────────────────────────────────────
# Keys match RMMType.value strings.

KNOWN_PATHS: dict[str, dict[str, list[str]]] = {
    "AnyDesk": {
        "windows": [
            "%APPDATA%\\AnyDesk",
            "%PROGRAMDATA%\\AnyDesk",
            "C:\\Users\\*\\AppData\\Roaming\\AnyDesk",
        ],
        "linux": ["~/.anydesk", "/etc/anydesk"],
        "macos": ["~/Library/Application Support/AnyDesk"],
    },
    "TeamViewer": {
        "windows": [
            "%APPDATA%\\TeamViewer",
            "%PROGRAMDATA%\\TeamViewer",
            "C:\\Program Files\\TeamViewer",
            "C:\\Program Files (x86)\\TeamViewer",
            "C:\\Users\\*\\AppData\\Roaming\\TeamViewer",
        ],
        "linux": [
            "/var/log/teamviewer*",
            "~/.config/teamviewer*",
            "/opt/teamviewer/logfiles",
        ],
        "macos": ["~/Library/Logs/TeamViewer"],
    },
    "ScreenConnect": {
        "windows": [
            "%PROGRAMDATA%\\ScreenConnect Client*",
            "%PROGRAMFILES%\\ScreenConnect Client*",
            "C:\\Windows\\Temp\\ScreenConnect*",
            "C:\\Users\\*\\Documents\\ConnectWise Control*",
        ],
        "linux": ["/opt/connectwisecontrol*"],
    },
    "Chrome Remote Desktop": {
        "windows": [
            "%LOCALAPPDATA%\\Google\\Chrome Remote Desktop",
            "%PROGRAMDATA%\\Google\\Chrome Remote Desktop",
        ],
        "linux": [
            "/var/log/chrome-remote-desktop*",
            "~/.config/chrome-remote-desktop",
        ],
        "macos": ["~/Library/Logs/Chrome Remote Desktop"],
    },
    "Splashtop": {
        "windows": [
            "%PROGRAMDATA%\\Splashtop\\Splashtop Remote\\",
            "%PROGRAMDATA%\\Splashtop\\Splashtop Software Updater\\",
            "%APPDATA%\\Splashtop\\",
        ],
    },
    "RustDesk": {
        "windows": [
            "%APPDATA%\\RustDesk\\",
            "%PROGRAMDATA%\\RustDesk\\",
            "C:\\Users\\*\\AppData\\Roaming\\RustDesk\\",
        ],
        "linux": ["~/.config/rustdesk", "/root/.config/rustdesk"],
    },
}

# ── Filename glob patterns ───────────────────────────────────────────────────
# Used for fast first-pass matching against filenames only.

FILE_PATTERNS: dict[str, list[str]] = {
    "AnyDesk": [
        "ad.trace",
        "ad_svc.trace",
        "connection_trace.txt",
    ],
    "TeamViewer": [
        "Connections_incoming.txt",
        "Connections.txt",
        "TeamViewer*_Logfile.log",
        "TeamViewer*_Logfile_OLD.log",
    ],
    "ScreenConnect": [
        "*.log",
        "SessionOutput.db",
        "user.config",
    ],
    "Chrome Remote Desktop": [
        "*.log",
        "chrome_remote_desktop.log*",
    ],
    "Splashtop": [
        "log_*.log",
        "SPLog.txt",
        "SRLog.txt",
    ],
    "RustDesk": [
        "*.log",
        "connection.log*",
    ],
}
