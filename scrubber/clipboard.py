"""Clipboard I/O via system tools (no pip deps). Linux (wl-clipboard/xclip/xsel), macOS, Windows."""
from __future__ import annotations

import shutil
import subprocess
import sys

_READERS = [["wl-paste", "--no-newline"], ["xclip", "-selection", "clipboard", "-o"],
            ["xsel", "--clipboard", "--output"], ["pbpaste"],
            ["powershell", "-NoProfile", "-Command", "Get-Clipboard -Raw"]]
_WRITERS = [["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"],
            ["pbcopy"], ["clip"]]


def _first(cmds):
    for c in cmds:
        if shutil.which(c[0]):
            return c
    sys.exit("No clipboard tool found. Install wl-clipboard (Wayland) or xclip (X11).")


def read() -> str:
    return subprocess.run(_first(_READERS), capture_output=True, check=True).stdout.decode("utf-8")


def write(text: str) -> None:
    cmd = _first(_WRITERS)
    # xclip/wl-copy fork to serve the selection; don't wait on their stdout
    subprocess.run(cmd, input=text.encode("utf-8"), check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
