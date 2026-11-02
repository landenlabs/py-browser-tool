#!/usr/bin/env python3
# ----------------------------------------------------------------------
# Copyright (c) 2026 LanDen Labs - Dennis Lang
# https://landenlabs.com
# ----------------------------------------------------------------------
"""brow-tool - Browser directory analysis and forensics tool"""

import argparse
import json
import os
import platform
import shutil
import sys
import traceback
from datetime import datetime, timedelta
from pathlib import Path

VERSION = "v6.05.23"


# ---------------------------------------------------------------------------
# Color support
# ---------------------------------------------------------------------------

_RED    = '\033[31m'
_RESET  = '\033[0m'
_YELLOW = '\033[33m'
_USE_COLOR = False


def _init_colors():
    """Enable ANSI color output if the terminal supports it."""
    global _USE_COLOR
    if os.environ.get('NO_COLOR'):
        return
    if not sys.stdout.isatty():
        return
    if sys.platform == 'win32':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong(0)
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        except Exception:
            return
    _USE_COLOR = True


def _c(text, color):
    """Wrap text in an ANSI color if colors are enabled."""
    return f"{color}{text}{_RESET}" if _USE_COLOR else text


# ---------------------------------------------------------------------------
# Default browser locations per OS
# ---------------------------------------------------------------------------

def get_default_chrome_paths():
    """Return existing default Chrome User Data locations for the current OS."""
    system = platform.system()
    candidates = []

    if system == 'Windows':
        local = os.environ.get('LOCALAPPDATA')
        if local:
            base = Path(local)
            candidates += [
                base / 'Google' / 'Chrome'      / 'User Data',
                base / 'Google' / 'Chrome Beta' / 'User Data',
                base / 'Google' / 'Chrome SxS'  / 'User Data',   # Canary
                base / 'Chromium'               / 'User Data',
            ]
    elif system == 'Darwin':
        home = Path.home()
        support = home / 'Library' / 'Application Support'
        candidates += [
            support / 'Google' / 'Chrome',
            support / 'Google' / 'Chrome Beta',
            support / 'Google' / 'Chrome Canary',
            support / 'Chromium',
        ]
    else:  # Linux / *BSD
        home = Path.home()
        cfg  = home / '.config'
        candidates += [
            cfg / 'google-chrome',
            cfg / 'google-chrome-beta',
            cfg / 'google-chrome-unstable',
            cfg / 'chromium',
        ]

    return [p for p in candidates if p.exists()]


def get_default_chrome_path():
    """Return the first existing default Chrome User Data location for the current OS, or None."""
    paths = get_default_chrome_paths()
    return paths[0] if paths else None


# ---------------------------------------------------------------------------
# Manifest parsing
# ---------------------------------------------------------------------------

def _resolve_message(ext_root, value, default_locale):
    """
    Resolve a Chrome '__MSG_key__' string by reading the extension's
    _locales/<locale>/messages.json. Returns the resolved string, or the
    original value if it isn't a message reference or can't be resolved.

    Chrome's lookup order: current UI locale → language family → default_locale.
    Without access to the running browser's UI locale we try, in order:
    default_locale, its language family, and a handful of common fallbacks.
    """
    if not isinstance(value, str):
        return value
    if not (value.startswith('__MSG_') and value.endswith('__')):
        return value

    key = value[6:-2]  # strip '__MSG_' and '__'
    if not key:
        return value

    locales_dir = ext_root / '_locales'
    if not _safe_exists(locales_dir):
        return value

    candidates = []
    if default_locale:
        candidates.append(default_locale)
        candidates.append(default_locale.replace('-', '_'))
        family = default_locale.split('-')[0].split('_')[0]
        if family and family not in candidates:
            candidates.append(family)
    # Common fallbacks for extensions that misdeclare or omit default_locale
    for loc in ('en', 'en_US', 'en_GB'):
        if loc not in candidates:
            candidates.append(loc)

    for loc in candidates:
        messages = locales_dir / loc / 'messages.json'
        if not _safe_exists(messages):
            continue
        try:
            with open(messages, 'r', encoding='utf-8-sig', errors='ignore') as f:
                data = json.load(f)
        except (OSError, ValueError):
            continue
        # Chrome message-key lookup is case-insensitive
        target = key.lower()
        for k, entry in data.items():
            if k.lower() == target and isinstance(entry, dict):
                msg = entry.get('message')
                if msg:
                    return msg
    return value  # leave the __MSG_...__ form so the caller can flag it


def get_extension_details(manifest_path):
    """Parse manifest.json and return (name, version, description, manifest_version)."""
    try:
        with open(manifest_path, 'r', encoding='utf-8-sig', errors='ignore') as f:
            data = json.load(f)

        name = data.get('name', 'Unknown')
        version = data.get('version', 'Unknown')
        description = data.get('description', 'No description provided.')
        manifest_version = data.get('manifest_version')  # int (typically 2 or 3); may be missing
        default_locale = data.get('default_locale')

        ext_root = Path(manifest_path).parent
        resolved_name = _resolve_message(ext_root, name, default_locale)
        resolved_desc = _resolve_message(ext_root, description, default_locale)

        # If resolution failed, mark the raw key so it's still readable
        if resolved_name is name and isinstance(name, str) \
                and name.startswith('__MSG_') and name.endswith('__'):
            resolved_name = f"{name} (unresolved)"
        if resolved_desc is description and isinstance(description, str) \
                and description.startswith('__MSG_') and description.endswith('__'):
            resolved_desc = f"{description} (unresolved)"

        return resolved_name, version, resolved_desc, manifest_version
    except Exception:
        return "Unreadable Manifest", "Unknown", "Could not parse JSON.", None


def read_manifest_version(manifest_path):
    """Return just the manifest_version field from a manifest.json, or None."""
    try:
        with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        return data.get('manifest_version')
    except (OSError, ValueError):
        return None


def load_extension_settings(profile_dir):
    """
    Return the merged 'extensions.settings' dict (ext_id -> info) for a profile.

    Chrome historically stored per-extension settings (state, install_time, ...)
    in 'Preferences'; newer versions moved them to 'Secure Preferences'. Merge
    both so callers see settings regardless of which file the running Chrome
    version uses.
    """
    settings = {}
    for fname in ('Preferences', 'Secure Preferences'):
        path = profile_dir / fname
        if not _safe_exists(path):
            continue
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            settings.update(data.get('extensions', {}).get('settings', {}) or {})
        except (OSError, ValueError):
            continue
    return settings


_CHROME_EPOCH = datetime(1601, 1, 1)


def chrome_time_to_datetime(value):
    """Convert a Chrome/WebKit timestamp (microseconds since 1601-01-01 UTC) to a datetime, or None."""
    try:
        micros = int(value)
    except (TypeError, ValueError):
        return None
    if micros <= 0:
        return None
    try:
        return _CHROME_EPOCH + timedelta(microseconds=micros)
    except OverflowError:
        return None


def get_extension_install_date(ext_id, settings, manifest_path):
    """
    Return a display string for when an extension was installed.

    Prefers the 'first_install_time' Chrome recorded for this extension in
    Preferences / Secure Preferences; falls back to the manifest.json file's
    creation time (birth time where the OS tracks it, else last metadata
    change time) when Chrome has no install-time record.
    """
    info = settings.get(ext_id) or {}
    installed = chrome_time_to_datetime(info.get('first_install_time'))
    if installed:
        return installed.strftime('%Y-%m-%d %H:%M:%S')

    try:
        stat = os.stat(manifest_path)
        ts = getattr(stat, 'st_birthtime', None) or stat.st_ctime
        return f"{datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')}  (manifest file date)"
    except OSError:
        return "Unknown"


# ---------------------------------------------------------------------------
# Chrome scanning
# ---------------------------------------------------------------------------

def _safe_iterdir(path):
    """Iterate a directory, returning [] on permission / OS errors."""
    try:
        return list(path.iterdir())
    except (PermissionError, OSError) as err:
        print(f"  [!] Skipping (cannot list): {path}  ({err.strerror or err})", file=sys.stderr)
        return []


def _safe_exists(path):
    """Test path existence, treating permission errors as 'inaccessible' rather than crashing."""
    try:
        return path.exists()
    except (PermissionError, OSError):
        return False


def compute_dir_size(path):
    """Recursively sum file sizes under path, skipping inaccessible entries and symlinks."""
    total = 0
    try:
        entries = list(os.scandir(path))
    except (PermissionError, OSError):
        return 0
    for entry in entries:
        try:
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                total += compute_dir_size(entry.path)
            else:
                total += entry.stat(follow_symlinks=False).st_size
        except (PermissionError, OSError):
            continue
    return total


def format_size(num_bytes):
    """Human-readable size string, e.g. '512 B', '4.3 MB', '1.2 GB'."""
    size = float(num_bytes)
    for unit in ('B', 'KB', 'MB', 'GB'):
        if size < 1024:
            return f"{size:.0f} {unit}" if unit == 'B' else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def get_chrome_version(root_path):
    """
    Return the Chrome version string recorded in this User Data directory, or None.

    Reads '<User Data>/Last Version' — a single-line text file Chrome writes after
    a successful launch (e.g. '131.0.6778.85'). This reflects the version that
    last ran with this profile set, which is what these extensions were validated
    against.
    """
    last_version = root_path / 'Last Version'
    if not _safe_exists(last_version):
        return None
    try:
        with open(last_version, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read().strip() or None
    except OSError:
        return None


def get_min_manifest_version(chrome_version):
    """
    Given a Chrome version string, return the minimum extension manifest_version
    that Chrome will load, plus a short note string.

    Returns (min_mv, note) or (None, None) if the version can't be parsed.

    Timeline:
      Chrome 127 (Jun 2024): Manifest V2 disabled by default for users
      Chrome 138 (Jun 2025): Manifest V2 fully removed
    """
    if not chrome_version:
        return None, None
    try:
        major = int(chrome_version.split('.')[0])
    except (ValueError, IndexError):
        return None, None
    if major >= 138:
        return 3, "Manifest V2 removed"
    if major >= 127:
        return 3, "Manifest V2 disabled by default"
    return 2, "Manifest V2 and V3 supported"


def print_chrome_header(root_path):
    """Print the Chrome version + minimum supported manifest_version line."""
    version = get_chrome_version(root_path)
    if version is None:
        print(f"[*] Chrome version: (unknown — no 'Last Version' file in {root_path})")
        return
    min_mv, note = get_min_manifest_version(version)
    if min_mv is None:
        print(f"[*] Chrome version: {version}  (minimum extension manifest_version: unknown)")
    else:
        print(f"[*] Chrome version: {version}  "
              f"(minimum extension manifest_version: {min_mv} — {note})")


def load_chrome_profile_names(root_path):
    """
    Return a {profile_dir_name: display_name} mapping for a Chrome User Data root.

    Tries 'Local State' first (one read covers all profiles); falls back to each
    profile's own 'Preferences' file. Returns {} on any failure.
    """
    mapping = {}

    local_state = root_path / 'Local State'
    if _safe_exists(local_state):
        try:
            with open(local_state, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            info_cache = data.get('profile', {}).get('info_cache', {}) or {}
            for dir_name, info in info_cache.items():
                display = info.get('name') or info.get('shortcut_name') or info.get('gaia_name')
                if display:
                    mapping[dir_name] = display
        except (OSError, ValueError):
            pass

    # Fallback: per-profile Preferences for anything still missing
    for profile_item in _safe_iterdir(root_path):
        if profile_item.name in mapping:
            continue
        try:
            if not profile_item.is_dir():
                continue
        except (PermissionError, OSError):
            continue
        if not (profile_item.name == 'Default' or profile_item.name.startswith('Profile')):
            continue
        prefs = profile_item / 'Preferences'
        if not _safe_exists(prefs):
            continue
        try:
            with open(prefs, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            display = data.get('profile', {}).get('name')
            if display:
                mapping[profile_item.name] = display
        except (OSError, ValueError):
            continue

    return mapping


def scan_chrome_directory(chrome_dir, profile_filter=None):
    """Scan a Chrome user-data folder for profiles and their extensions.

    profile_filter, if given, limits the scan to the one profile whose internal
    name (e.g. 'Profile 10') or display name (e.g. 'Work') matches (case-insensitive).
    """
    root_path = Path(chrome_dir)
    if not _safe_exists(root_path):
        print(f"[-] Error: The path '{chrome_dir}' does not exist.", file=sys.stderr)
        return 0

    print_chrome_header(root_path)
    print(f"[*] Scanning for extensions in: {root_path}\n")

    profile_names = load_chrome_profile_names(root_path)
    chrome_version = get_chrome_version(root_path)
    min_mv, _ = get_min_manifest_version(chrome_version)

    extensions_found = 0
    skipped = 0
    total_size = 0
    profiles_matched = 0

    for profile_item in sorted(_safe_iterdir(root_path), key=lambda p: p.name.lower()):
        # Standard profiles are named 'Default' or 'Profile X'
        try:
            if not (profile_item.is_dir() and
                    (profile_item.name == 'Default' or profile_item.name.startswith('Profile'))):
                continue
        except (PermissionError, OSError):
            continue

        display = profile_names.get(profile_item.name, '')
        if not _profile_matches(profile_item.name, display, profile_filter):
            continue

        extensions_dir = profile_item / "Extensions"
        if not (_safe_exists(extensions_dir) and extensions_dir.is_dir()):
            continue

        profiles_matched += 1
        header_label = f'{profile_item.name}  ("{display}")' if display else profile_item.name
        profile_field = f'{profile_item.name}  ("{display}")' if display else profile_item.name
        print(f"=== Profile: {header_label} ===")
        profile_has_extensions = False
        ext_settings = load_extension_settings(profile_item)

        for ext_id_dir in _safe_iterdir(extensions_dir):
            try:
                if not ext_id_dir.is_dir():
                    continue
            except (PermissionError, OSError):
                skipped += 1
                continue

            # Extensions have version subfolders which house the manifest.json
            for version_dir in _safe_iterdir(ext_id_dir):
                manifest_file = version_dir / "manifest.json"
                if not _safe_exists(manifest_file):
                    # May be a permission denial on a component extension; count and move on
                    try:
                        if not version_dir.is_dir():
                            continue
                    except (PermissionError, OSError):
                        pass
                    continue

                profile_has_extensions = True
                extensions_found += 1

                name, version, desc, mv = get_extension_details(manifest_file)
                size = compute_dir_size(version_dir)
                total_size += size
                install_date = get_extension_install_date(ext_id_dir.name, ext_settings, manifest_file)

                if mv is None:
                    mv_display = "(none)"
                elif min_mv is not None and mv < min_mv:
                    mv_display = _c(f"{mv}  (UNSUPPORTED — below browser minimum {min_mv})", _RED)
                else:
                    mv_display = str(mv)

                print(f"  Name             : {name}")
                print(f"  Version          : {version}")
                print(f"  Manifest Version : {mv_display}")
                print(f"  Description      : {desc}")
                print(f"  Disk Space       : {format_size(size)}")
                print(f"  Install Date     : {install_date}")
                print(f"  Profile          : {profile_field} (Enabled/Installed)")
                print(f"  Path             : {manifest_file}")
                print("-" * 50)

        if not profile_has_extensions:
            print("  (No user extensions found in this profile)")
            print("-" * 50)
        print()

    if profile_filter and profiles_matched == 0:
        print(f"  (no profile matching '{profile_filter}' found)\n")
        return 0

    if extensions_found == 0:
        print("[-] No active profile extensions detected. (Component updates ignored)\n")
    else:
        print(f"[*] Total disk space used by {extensions_found} "
              f"extension{'s' if extensions_found != 1 else ''}: {format_size(total_size)}\n")

    if skipped:
        print(f"[!] {skipped} extension entr{'y' if skipped == 1 else 'ies'} "
              f"could not be accessed (permission denied).\n", file=sys.stderr)

    return extensions_found


def scan_chrome(chrome_arg, profile_filter=None):
    """Dispatch a Chrome scan: explicit path, or the first default OS location found."""
    if chrome_arg and chrome_arg != 'AUTO':
        return scan_chrome_directory(chrome_arg, profile_filter)

    path = get_default_chrome_path()
    if not path:
        print(f"[-] No Chrome installation found in standard locations "
              f"for {platform.system()}.", file=sys.stderr)
        return 0

    print(f"[*] No --chrome path given; using default location for "
          f"{platform.system()}: {path}\n")
    return scan_chrome_directory(str(path), profile_filter)


# ---------------------------------------------------------------------------
# Per-profile extension counts
# ---------------------------------------------------------------------------

def count_profile_extensions(profile_dir, min_mv=None):
    """
    Return (installed, enabled, unsupported) for a profile dir.

    'installed'   = extension IDs under Extensions/ that have at least one
                    version subfolder containing manifest.json.
    'enabled'     = installed IDs whose Preferences 'extensions.settings.<id>.state'
                    is 1. If state is missing the extension is treated as enabled.
    'unsupported' = installed IDs whose manifest_version is below min_mv (the
                    minimum the running Chrome will load). 0 if min_mv is None.
    """
    extensions_dir = profile_dir / "Extensions"
    # Map ext_id -> manifest_version (int or None) for the chosen version dir
    installed = {}
    if _safe_exists(extensions_dir) and extensions_dir.is_dir():
        for ext_id_dir in _safe_iterdir(extensions_dir):
            try:
                if not ext_id_dir.is_dir():
                    continue
            except (PermissionError, OSError):
                continue
            # Prefer the highest-named version dir (Chrome's selection rule)
            version_dirs = sorted(
                (d for d in _safe_iterdir(ext_id_dir) if _safe_exists(d / "manifest.json")),
                key=lambda d: d.name,
                reverse=True,
            )
            if not version_dirs:
                continue
            mv = read_manifest_version(version_dirs[0] / "manifest.json")
            installed[ext_id_dir.name] = mv

    settings = load_extension_settings(profile_dir)

    enabled = 0
    for ext_id in installed:
        info = settings.get(ext_id) or {}
        # state: 0=disabled, 1=enabled, missing → treat as enabled
        if info.get('state', 1) == 1:
            enabled += 1

    unsupported = 0
    if min_mv is not None:
        for mv in installed.values():
            if mv is not None and mv < min_mv:
                unsupported += 1

    return len(installed), enabled, unsupported


def list_profile_subdirs(profile_path):
    """Return [(entry_name, size)] for each direct child of profile_path, sorted by size desc."""
    rows = []
    for entry in _safe_iterdir(profile_path):
        try:
            if entry.is_symlink():
                continue
            size = compute_dir_size(entry) if entry.is_dir() else entry.stat().st_size
        except (PermissionError, OSError):
            continue
        rows.append((entry.name, size))
    rows.sort(key=lambda r: r[1], reverse=True)
    return rows


def print_profile_space_detail(profile_item, display, size):
    """Print the path and per-sub-directory size breakdown for one profile (--verbose --space)."""
    header_label = f'{profile_item.name}  ("{display}")' if display else profile_item.name
    print(f"=== Profile: {header_label} ===")
    print(f"  Path: {profile_item}\n")

    subdirs = list_profile_subdirs(profile_item)
    if subdirs:
        sub_name_w = max(len("Sub-directory"), max(len(n) for n, _ in subdirs))
        sub_size_w = max(len("Size"), max(len(format_size(s)) for _, s in subdirs))
        print(f"  {'Sub-directory'.ljust(sub_name_w)}   {'Size'.rjust(sub_size_w)}")
        print(f"  {'-' * sub_name_w}   {'-' * sub_size_w}")
        for name, s in subdirs:
            print(f"  {name.ljust(sub_name_w)}   {format_size(s).rjust(sub_size_w)}")
    else:
        print("  (empty)")
    print(f"\n  Profile total: {format_size(size)}\n")


def _profile_matches(dir_name, display_name, filter_name):
    """True if filter_name (case-insensitive) equals the profile's internal or display name."""
    if not filter_name:
        return True
    target = filter_name.lower()
    return dir_name.lower() == target or (display_name and display_name.lower() == target)


def list_chrome_profiles_directory(chrome_dir, show_extensions=True, show_space=False, verbose=False,
                                    profile_filter=None):
    """List profiles in a Chrome user-data folder with extension counts and/or disk space.

    profile_filter, if given, limits the listing to the one profile whose internal
    name (e.g. 'Profile 10') or display name (e.g. 'Work') matches (case-insensitive).
    """
    root_path = Path(chrome_dir)
    if not _safe_exists(root_path):
        print(f"[-] Error: The path '{chrome_dir}' does not exist.", file=sys.stderr)
        return 0

    print_chrome_header(root_path)
    print(f"[*] Profiles in: {root_path}\n")

    profile_names  = load_chrome_profile_names(root_path)
    chrome_version = get_chrome_version(root_path)
    min_mv, _      = get_min_manifest_version(chrome_version)

    rows = []
    for profile_item in sorted(_safe_iterdir(root_path), key=lambda p: p.name.lower()):
        try:
            if not profile_item.is_dir():
                continue
        except (PermissionError, OSError):
            continue
        if not (profile_item.name == 'Default' or profile_item.name.startswith('Profile')):
            continue

        display = profile_names.get(profile_item.name, '')
        if not _profile_matches(profile_item.name, display, profile_filter):
            continue
        installed = enabled = unsupported = 0
        if show_extensions:
            installed, enabled, unsupported = count_profile_extensions(profile_item, min_mv)
        size = compute_dir_size(profile_item) if show_space else 0
        rows.append((profile_item.name, display, installed, enabled, unsupported, size))

        if show_space and verbose:
            print_profile_space_detail(profile_item, display, size)

    if not rows:
        if profile_filter:
            print(f"  (no profile matching '{profile_filter}' found)\n")
        else:
            print("  (no profiles found)\n")
        return 0

    name_w    = max(len("Profile"),      max(len(r[0]) for r in rows))
    display_w = max(len("Display Name"), max(len(r[1]) for r in rows))
    unsup_label = "Unsupported" if min_mv is not None else "Unsupported*"
    size_w = max(len("Disk Space"), max((len(format_size(r[5])) for r in rows), default=0)) \
        if show_space else 0

    header = f"  {'Profile'.ljust(name_w)}   {'Display Name'.ljust(display_w)}"
    sep    = f"  {'-' * name_w}   {'-' * display_w}"
    if show_extensions:
        header += f"   Installed   Enabled   {unsup_label}"
        sep    += f"   ---------   -------   {'-' * len(unsup_label)}"
    if show_space:
        header += f"   {'Disk Space'.rjust(size_w)}"
        sep    += f"   {'-' * size_w}"
    print(header)
    print(sep)

    total_size = 0
    for name, display, installed, enabled, unsupported, size in rows:
        line = f"  {name.ljust(name_w)}   {display.ljust(display_w)}"
        if show_extensions:
            unsup_cell = f"{unsupported:>{len(unsup_label)}}"
            if min_mv is not None and unsupported > 0:
                unsup_cell = _c(unsup_cell, _RED)
            line += f"   {installed:>9}   {enabled:>7}   {unsup_cell}"
        if show_space:
            line += f"   {format_size(size).rjust(size_w)}"
            total_size += size
        print(line)
    if show_extensions and min_mv is None:
        print("\n  * Cannot evaluate: Chrome version unknown, so no minimum manifest_version baseline.")
    if show_space:
        print(f"\n  Total disk space: {format_size(total_size)}")
    print()
    return len(rows)


def list_chrome_profiles(chrome_arg, show_extensions=True, show_space=False, verbose=False,
                          profile_filter=None):
    """Dispatch a Chrome profile listing: explicit path, or the first default OS location found."""
    if chrome_arg and chrome_arg != 'AUTO':
        return list_chrome_profiles_directory(chrome_arg, show_extensions, show_space, verbose,
                                               profile_filter)

    path = get_default_chrome_path()
    if not path:
        print(f"[-] No Chrome installation found in standard locations "
              f"for {platform.system()}.", file=sys.stderr)
        return 0

    print(f"[*] No --chrome path given; using default location for "
          f"{platform.system()}: {path}\n")
    return list_chrome_profiles_directory(str(path), show_extensions, show_space, verbose,
                                           profile_filter)


# ---------------------------------------------------------------------------
# Profile cleaning
# ---------------------------------------------------------------------------

CLEAN_TARGETS = [
    'Cache', 'Download Service', 'Service Worker', 'Sessions', 'Cookies', 'History',
    'Reporting and NEL', 'Network Action Predictor', 'Favicons', 'Conversions',
    'DawnGraphiteCache', 'GPUCache', 'DawnWebGPUCache', 'InterestGroups',
    'Visited Links', 'Affiliation Database',
]


def _path_size(path):
    """Size of a file, or recursive size of a directory."""
    try:
        if path.is_dir():
            return compute_dir_size(path)
        return path.stat().st_size
    except (PermissionError, OSError):
        return 0


def _remove_path(path):
    """Delete a file or directory tree."""
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def _iter_profile_dirs(root_path):
    """Yield (name, Path) for each standard profile dir under a Chrome User Data root."""
    for profile_item in sorted(_safe_iterdir(root_path), key=lambda p: p.name.lower()):
        try:
            if not (profile_item.is_dir() and
                    (profile_item.name == 'Default' or profile_item.name.startswith('Profile'))):
                continue
        except (PermissionError, OSError):
            continue
        yield profile_item.name, profile_item


def clean_chrome_directory(chrome_dir, target, assume_yes=False):
    """Remove the items listed in CLEAN_TARGETS for one or all profiles."""
    root_path = Path(chrome_dir)
    if not _safe_exists(root_path):
        print(f"[-] Error: The path '{chrome_dir}' does not exist.", file=sys.stderr)
        return 0

    all_profiles = list(_iter_profile_dirs(root_path))
    if target.lower() == 'all':
        selected = all_profiles
    else:
        profile_names = load_chrome_profile_names(root_path)
        selected = [(n, p) for n, p in all_profiles
                    if _profile_matches(n, profile_names.get(n, ''), target)]
        if not selected:
            print(f"[-] Error: Profile '{target}' not found under {root_path}.", file=sys.stderr)
            return 0

    to_remove = []
    for name, profile_path in selected:
        for sub in CLEAN_TARGETS:
            sub_path = profile_path / sub
            if _safe_exists(sub_path):
                to_remove.append((name, sub_path))

    if not to_remove:
        print(f"[*] Nothing to clean in {root_path}.\n")
        return 0

    print(f"[*] The following will be removed from {root_path}:")
    total_size = 0
    sized = []
    for name, sub_path in to_remove:
        size = _path_size(sub_path)
        total_size += size
        sized.append((name, sub_path, size))
    name_w = max(len(n) for n, _, _ in sized)
    for name, sub_path, size in sized:
        print(f"  {name.ljust(name_w)}   {sub_path.name:<16}   {format_size(size):>10}   {sub_path}")
    print(f"\n  Total space to be reclaimed: {format_size(total_size)}\n")

    if not assume_yes:
        answer = input("Proceed with deletion? [y/N] ").strip().lower()
        if answer not in ('y', 'yes'):
            print("[*] Aborted, nothing removed.\n")
            return 0

    removed = 0
    for _, sub_path, _ in sized:
        try:
            _remove_path(sub_path)
            removed += 1
        except OSError as err:
            print(f"  [!] Failed to remove {sub_path}: {err}", file=sys.stderr)
    print(f"\n[*] Removed {removed} of {len(sized)} item{'s' if len(sized) != 1 else ''}, "
          f"reclaiming up to {format_size(total_size)}.\n")
    return removed


def clean_chrome(chrome_arg, target, assume_yes=False):
    """Dispatch a Chrome clean: explicit path, or the first default OS location found."""
    if chrome_arg and chrome_arg != 'AUTO':
        return clean_chrome_directory(chrome_arg, target, assume_yes)

    path = get_default_chrome_path()
    if not path:
        print(f"[-] No Chrome installation found in standard locations "
              f"for {platform.system()}.", file=sys.stderr)
        return 0

    print(f"[*] No --chrome path given; using default location for "
          f"{platform.system()}: {path}\n")
    return clean_chrome_directory(str(path), target, assume_yes)


# ---------------------------------------------------------------------------
# Bookmark verification
# ---------------------------------------------------------------------------

# HTTP statuses that mean "the server answered but refuses automated clients";
# the page probably exists, so these are reported but never deleted.
BLOCKED_STATUSES = {401, 403, 429, 999}
BOOKMARK_USER_AGENT = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                       '(KHTML, like Gecko) Chrome/124.0 Safari/537.36')


def extract_bookmark_urls(node, folder='', out=None):
    """Walk a Chrome Bookmarks JSON tree; return a list of (guid, name, url, folder)."""
    if out is None:
        out = []
    if isinstance(node, dict):
        if node.get('type') == 'url':
            out.append((node.get('guid', ''), node.get('name', ''), node.get('url', ''), folder))
        elif 'children' in node:
            sub = f"{folder}/{node.get('name', '')}" if folder else node.get('name', '')
            for child in node['children']:
                extract_bookmark_urls(child, sub, out)
        else:
            # Top-level container: {'roots': {'bookmark_bar': {...}, ...}}
            for value in node.values():
                if isinstance(value, (dict, list)):
                    extract_bookmark_urls(value, folder, out)
    elif isinstance(node, list):
        for item in node:
            extract_bookmark_urls(item, folder, out)
    return out


def check_url(url, timeout):
    """Return (status, detail). status is an int HTTP code, or None on a network error."""
    import ssl
    import urllib.error
    import urllib.request

    ctx = ssl.create_default_context()
    last = (None, '')
    for method in ('HEAD', 'GET'):
        req = urllib.request.Request(url, method=method, headers={'User-Agent': BOOKMARK_USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.status, resp.reason
        except urllib.error.HTTPError as err:
            last = (err.code, str(err.reason))
            # Many servers mishandle HEAD; retry those with GET before judging.
            if method == 'HEAD' and err.code >= 400:
                continue
            return last
        except Exception as err:  # DNS failure, refused, TLS error, timeout, bad URL ...
            reason = getattr(err, 'reason', err)
            last = (None, f"{type(reason).__name__}: {reason}")
            if method == 'HEAD':
                continue
            return last
    return last


def _classify(status):
    if status is None:
        return 'failed'
    if status < 400:
        return 'ok'
    if status in BLOCKED_STATUSES:
        return 'blocked'
    return 'failed'


def delete_bookmarks_from_file(bookmarks_path, guids):
    """Remove bookmark entries with the given guids; back up the file first. Returns count removed."""
    with open(bookmarks_path, 'r', encoding='utf-8') as fh:
        data = json.load(fh)

    removed = 0

    def prune(node):
        nonlocal removed
        children = node.get('children')
        if not isinstance(children, list):
            return
        kept = []
        for child in children:
            if child.get('type') == 'url' and child.get('guid') in guids:
                removed += 1
            else:
                prune(child)
                kept.append(child)
        node['children'] = kept

    for root in data.get('roots', {}).values():
        if isinstance(root, dict):
            prune(root)

    backup = Path(str(bookmarks_path) + '.' + datetime.now().strftime('%Y%m%d-%H%M%S') + '.bak')
    shutil.copy2(bookmarks_path, backup)
    # Chrome recomputes the checksum when it is absent; a stale one is treated as corruption.
    data.pop('checksum', None)
    with open(bookmarks_path, 'w', encoding='utf-8') as fh:
        json.dump(data, fh, indent=3, ensure_ascii=False)
    print(f"  [*] Backup saved to {backup}")
    return removed


def check_profile_bookmarks(name, display, profile_path, delete=False, assume_yes=False,
                            timeout=10, workers=16):
    """Verify every http(s) bookmark in one profile; optionally delete the failed ones."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    bookmarks_path = profile_path / 'Bookmarks'
    label = f"{name} ({display})" if display else name
    if not _safe_exists(bookmarks_path):
        print(f"[*] {label}: no Bookmarks file.\n")
        return 0

    try:
        with open(bookmarks_path, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
    except (OSError, ValueError) as err:
        print(f"[-] {label}: cannot read {bookmarks_path}: {err}", file=sys.stderr)
        return 0

    entries = extract_bookmark_urls(data.get('roots', {}))
    checkable = [e for e in entries if e[2].lower().startswith(('http://', 'https://'))]
    print(f"[*] {label}: checking {len(checkable)} of {len(entries)} bookmarks "
          f"(skipping non-http URLs)...")

    results = {}
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(check_url, e[2], timeout): e for e in checkable}
        for fut in as_completed(futures):
            entry = futures[fut]
            results[entry[0] or entry[2]] = (entry, fut.result())
            done += 1
            if sys.stdout.isatty():
                print(f"\r  {done}/{len(checkable)}", end='', flush=True)
    if sys.stdout.isatty() and checkable:
        print('\r' + ' ' * 20 + '\r', end='')

    failed, blocked = [], []
    for entry, (status, detail) in results.values():
        kind = _classify(status)
        if kind == 'failed':
            failed.append((entry, status, detail))
        elif kind == 'blocked':
            blocked.append((entry, status, detail))

    for entry, status, detail in sorted(failed, key=lambda f: (f[0][3], f[0][1])):
        code = status if status is not None else 'ERR'
        print(f"  {_c(f'[FAILED {code}]', _RED)} {entry[1]}\n      {entry[2]}\n"
              f"      folder: {entry[3]}  {detail}")
    for entry, status, _ in sorted(blocked, key=lambda f: (f[0][3], f[0][1])):
        print(f"  {_c(f'[BLOCKED {status}]', _YELLOW)} {entry[1]}: {entry[2]} (kept)")

    print(f"\n  {len(checkable) - len(failed) - len(blocked)} ok, {len(failed)} failed, "
          f"{len(blocked)} blocked/restricted (never deleted)\n")

    if not delete or not failed:
        return len(failed)

    print(f"  [!] Chrome must be closed, or it will overwrite the Bookmarks file on exit.")
    if not assume_yes:
        answer = input(f"  Delete {len(failed)} failed bookmark{'s' if len(failed) != 1 else ''} "
                       f"from {label}? [y/N] ").strip().lower()
        if answer not in ('y', 'yes'):
            print("  [*] Aborted, nothing removed.\n")
            return len(failed)

    try:
        removed = delete_bookmarks_from_file(bookmarks_path, {e[0] for e, _, _ in failed if e[0]})
    except (OSError, ValueError) as err:
        print(f"  [-] Failed to update {bookmarks_path}: {err}", file=sys.stderr)
        return len(failed)
    print(f"  [*] Deleted {removed} bookmark{'s' if removed != 1 else ''}. "
          f"If Chrome sync is on, they may reappear from the sync server.\n")
    return len(failed)


def check_bookmarks_directory(chrome_dir, target, delete=False, assume_yes=False, timeout=10):
    root_path = Path(chrome_dir)
    if not _safe_exists(root_path):
        print(f"[-] Error: The path '{chrome_dir}' does not exist.", file=sys.stderr)
        return
    profile_names = load_chrome_profile_names(root_path)
    selected = [(n, p) for n, p in _iter_profile_dirs(root_path)
                if target in (None, 'ALL') or _profile_matches(n, profile_names.get(n, ''), target)]
    if not selected:
        print(f"[-] Error: Profile '{target}' not found under {root_path}.", file=sys.stderr)
        return
    for name, path in selected:
        check_profile_bookmarks(name, profile_names.get(name, ''), path, delete, assume_yes, timeout)


def check_bookmarks(chrome_arg, target, delete=False, assume_yes=False, timeout=10):
    """Dispatch a bookmark check: explicit path, or the first default OS location found."""
    if chrome_arg and chrome_arg != 'AUTO':
        return check_bookmarks_directory(chrome_arg, target, delete, assume_yes, timeout)
    path = get_default_chrome_path()
    if not path:
        print(f"[-] No Chrome installation found in standard locations "
              f"for {platform.system()}.", file=sys.stderr)
        return
    print(f"[*] No --chrome path given; using default location for "
          f"{platform.system()}: {path}\n")
    return check_bookmarks_directory(str(path), target, delete, assume_yes, timeout)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=f"brow-tool {VERSION}\nBrowser directory analysis and forensics tool.",
        epilog="""Examples:
  # Scan Chrome at the first default OS-specific User Data location found:
  brow-tool.py --summary --chrome

  # Same, but limited to one profile, by display name or internal name:
  brow-tool.py --chrome --summary "Work"
  brow-tool.py --chrome --summary "Profile 10"

  # List profiles with installed/enabled extension counts:
  brow-tool.py --profiles --chrome

  # List profiles with disk space used by each profile's directory tree:
  brow-tool.py --space --chrome

  # Same, but limited to one profile, by display name or internal name:
  brow-tool.py --chrome --space "Work"
  brow-tool.py --chrome --space "Profile 10"

  # Same, plus each profile's path and a per-sub-directory size breakdown:
  brow-tool.py --space --verbose --chrome

  # Both at once:
  brow-tool.py --summary --profiles --chrome

  # Remove cache/telemetry items (see below for the full list) from every profile:
  brow-tool.py --clean=all --chrome

  # Remove those same items from just "Profile 1", by internal or display name:
  brow-tool.py --clean="Profile 1" --chrome
  brow-tool.py --clean="Work" --chrome

  # Check every http(s) bookmark and report the ones that fail to load:
  brow-tool.py --bookmarks --chrome
  brow-tool.py --bookmarks="Work" --chrome

  # Same, then offer to delete the failed ones (close Chrome first; a backup is kept):
  brow-tool.py --bookmarks --delete-failed --chrome
  brow-tool.py --bookmarks --delete-failed -y --chrome

  # Scan a specific Chrome User Data directory:
  brow-tool.py --summary --chrome "%LOCALAPPDATA%\\Google\\Chrome\\User Data"
  brow-tool.py --summary --chrome ~/.config/google-chrome
  brow-tool.py --summary --chrome "~/Library/Application Support/Google/Chrome"

Default locations checked (in order) when --chrome is given without a path;
the first one that exists is used:
  Windows:  %LOCALAPPDATA%\\Google\\Chrome\\User Data
            %LOCALAPPDATA%\\Google\\Chrome Beta\\User Data
            %LOCALAPPDATA%\\Google\\Chrome SxS\\User Data   (Canary)
            %LOCALAPPDATA%\\Chromium\\User Data
  macOS:    ~/Library/Application Support/Google/Chrome
            ~/Library/Application Support/Google/Chrome Beta
            ~/Library/Application Support/Google/Chrome Canary
            ~/Library/Application Support/Chromium
  Linux:    ~/.config/google-chrome
            ~/.config/google-chrome-beta
            ~/.config/google-chrome-unstable
            ~/.config/chromium

--clean removes these items from each selected profile:
  Cache                     (directory)
  Download Service          (directory)
  Service Worker            (directory)
  Sessions                  (directory)
  Cookies                   (file)
  History                   (file)
  Reporting and NEL         (file)
  Network Action Predictor  (file)
  Favicons                  (file)
  Conversions               (file)
  DawnGraphiteCache         (directory)
  GPUCache                  (directory)
  DawnWebGPUCache           (directory)
  InterestGroups            (file)
  Visited Links             (file)
  Affiliation Database      (file)

Notes:
  The --chrome path should point to the Chrome "User Data" directory, which
  contains profile subdirectories such as 'Default' and 'Profile 1'.
  Future versions may add --firefox and --opera switches with the same behavior.
""",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        '--summary',
        nargs='?',
        const='ALL',
        default=None,
        metavar='PROFILE',
        help='Provide a summary of profiles and their installed extensions, including disk '
             'space used by and install date of each. With no value, shows all profiles; '
             "with a value, shows only the profile matching that internal name "
             "(e.g. 'Profile 10') or display name (e.g. 'Work')",
    )
    parser.add_argument(
        '--profiles',
        action='store_true',
        help='List profile dir, browser display name, and installed/enabled extension counts',
    )
    parser.add_argument(
        '--space',
        nargs='?',
        const='ALL',
        default=None,
        metavar='PROFILE',
        help="Compute and show the disk space used by each profile's directory tree. "
             "With no value, shows all profiles; with a value, shows only the profile "
             "matching that internal name (e.g. 'Profile 10') or display name (e.g. 'Work')",
    )
    parser.add_argument(
        '--clean',
        metavar='all|PROFILE',
        default=None,
        help="Remove cache/telemetry items (see epilog for the full list) from 'all' "
             "profiles or a specific profile, matched by internal name "
             "(e.g. 'Profile 10') or display name (e.g. 'Work')",
    )
    parser.add_argument(
        '--bookmarks',
        nargs='?',
        const='ALL',
        default=None,
        metavar='PROFILE',
        help='Check every http(s) bookmark and report which fail to load (connection error, '
             '404, 5xx ...). 401/403/429 are reported as blocked and are never deleted. '
             'With no value, checks all profiles; with a value, only the matching profile',
    )
    parser.add_argument(
        '--delete-failed',
        action='store_true',
        help='With --bookmarks, delete the failed bookmarks (asks first; backs up the '
             'Bookmarks file; close Chrome beforehand)',
    )
    parser.add_argument(
        '--timeout',
        type=float,
        default=10,
        metavar='SECONDS',
        help='With --bookmarks, per-request timeout (default: 10)',
    )
    parser.add_argument(
        '-y', '--yes',
        action='store_true',
        help='Skip the confirmation prompt when using --clean or --delete-failed',
    )
    parser.add_argument(
        '--chrome',
        nargs='?',
        const='AUTO',
        default=None,
        metavar='PATH',
        help='Scan Chrome. With no value, uses the first existing OS default User Data '
             'location; with a value, scans the given path.',
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='With --space, also show each profile\'s path and the size of its sub-directories',
    )
    parser.add_argument(
        '--no-color', action='store_true',
        help='Disable colored output (also honors the NO_COLOR env var)',
    )
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')

    args = parser.parse_args()

    if not args.no_color:
        _init_colors()

    if args.chrome is None:
        parser.error("at least one browser must be specified (e.g., --chrome)")

    if not (args.summary is not None or args.profiles or args.space is not None or args.clean
            or args.bookmarks is not None):
        parser.error("specify at least one of --summary, --profiles, --space, --clean, or --bookmarks")

    if args.delete_failed and args.bookmarks is None:
        parser.error("--delete-failed requires --bookmarks")

    if args.profiles or args.space is not None:
        profile_filter = args.space if args.space not in (None, 'ALL') else None
        list_chrome_profiles(args.chrome, show_extensions=args.profiles, show_space=args.space is not None,
                              verbose=args.verbose, profile_filter=profile_filter)

    if args.summary is not None:
        profile_filter = args.summary if args.summary != 'ALL' else None
        scan_chrome(args.chrome, profile_filter=profile_filter)

    if args.clean:
        clean_chrome(args.chrome, args.clean, assume_yes=args.yes)

    if args.bookmarks is not None:
        check_bookmarks(args.chrome, args.bookmarks, delete=args.delete_failed,
                        assume_yes=args.yes, timeout=args.timeout)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)
