from __future__ import annotations

import os
import platform
import shlex
import shutil
import subprocess
import sys
from pathlib import Path


CONSOLE_CHILD_ENV = "AGENTFTP_CONSOLE_CHILD"


def should_relaunch_in_console(
    mode: str,
    *,
    stdin_isatty: bool | None = None,
    stdout_isatty: bool | None = None,
    is_child: bool | None = None,
    has_visible_console: bool | None = None,
    system: str | None = None,
) -> bool:
    if mode == "no":
        return False
    if is_child is None:
        is_child = os.environ.get(CONSOLE_CHILD_ENV) == "1"
    if is_child:
        return False
    if mode == "auto":
        if stdin_isatty is None:
            stdin_isatty = sys.stdin.isatty()
        if stdout_isatty is None:
            stdout_isatty = sys.stdout.isatty()
        if stdin_isatty and stdout_isatty:
            return False
        resolved_system = (system or platform.system()).lower()
        if resolved_system == "windows":
            if has_visible_console is None:
                has_visible_console = windows_visible_console_attached()
            if has_visible_console:
                return False
    return mode in ("auto", "yes")


def windows_visible_console_attached() -> bool:
    if platform.system().lower() != "windows":
        return False
    try:
        import ctypes

        window = ctypes.windll.kernel32.GetConsoleWindow()
        return bool(window and ctypes.windll.user32.IsWindowVisible(window))
    except Exception:
        return False


def relaunch_in_console_if_needed(argv: list[str], *, mode: str, cwd: Path | None = None) -> bool:
    if not should_relaunch_in_console(mode):
        return False
    env = dict(os.environ)
    env[CONSOLE_CHILD_ENV] = "1"
    command = [sys.executable, "-m", "agentftp", *argv]
    try:
        open_console(command, cwd=(cwd or Path.cwd()).resolve(), env=env)
    except OSError as exc:
        print(f"agentFTP could not open a new console window: {exc}")
        print("Continuing in the current process.")
        return False
    print("agentFTP opened in a new console window.")
    return True


def open_console(command: list[str], *, cwd: Path, env: dict[str, str]) -> None:
    system = platform.system().lower()
    if system == "windows":
        subprocess.Popen(
            command,
            cwd=str(cwd),
            env=env,
            creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
        )
        return
    if system == "darwin":
        if not shutil.which("osascript"):
            raise OSError("osascript is not available")
        shell_command = "cd " + shlex.quote(str(cwd)) + " && " + " ".join(
            shlex.quote(part) for part in command
        )
        escaped = shell_command.replace("\\", "\\\\").replace('"', '\\"')
        subprocess.Popen(
            [
                "osascript",
                "-e",
                f'tell application "Terminal" to do script "{escaped}"',
                "-e",
                'tell application "Terminal" to activate',
            ],
            env=env,
        )
        return
    terminal_commands = [
        ["x-terminal-emulator", "-e", *command],
        ["gnome-terminal", "--", *command],
        ["konsole", "-e", *command],
        ["xterm", "-e", *command],
    ]
    for candidate in terminal_commands:
        if shutil.which(candidate[0]):
            subprocess.Popen(candidate, cwd=str(cwd), env=env)
            return
    raise OSError("no supported terminal emulator was found")
