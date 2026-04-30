from __future__ import annotations

import base64
import errno
import hashlib
import hmac
import json
import os
import posixpath
import secrets
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from .filenames import (
    contains_control,
    filename_key,
    filename_policy,
    normalize_disk,
    normalize_wire,
)


DEFAULT_PORT = 7171
DEFAULT_UI_PORT = 7180
CHUNK_SIZE = 8 * 1024 * 1024
MAX_JSON_BODY = 1024 * 1024
MAX_UPLOAD_CHUNK = CHUNK_SIZE
MAX_DOWNLOAD_CHUNK = CHUNK_SIZE
PARTIAL_DIR_NAME = ".agentftp_partial"
INBOX_DIR_NAME = ".agentftp_inbox"
HANDOFF_DIR_NAME = ".agentftp_handoff"
STATE_DIR_NAME = ".agentftp"
RESERVED_DIR_NAMES = {PARTIAL_DIR_NAME, INBOX_DIR_NAME, HANDOFF_DIR_NAME, STATE_DIR_NAME}
AUTH_ITERATIONS = 200_000


class AgentFTPError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details or {}


@dataclass
class TransferJob:
    id: str
    kind: str
    state: str = "queued"
    total_bytes: int = 0
    done_bytes: int = 0
    current: str = ""
    error: str = ""
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    cancel_requested: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "state": self.state,
            "totalBytes": self.total_bytes,
            "doneBytes": self.done_bytes,
            "current": self.current,
            "error": self.error,
            "startedAt": self.started_at,
            "finishedAt": self.finished_at,
            "cancelRequested": self.cancel_requested,
        }

    def raise_if_cancelled(self) -> None:
        if self.cancel_requested:
            raise AgentFTPError(499, "cancelled", "Transfer was cancelled")


def make_token() -> str:
    return secrets.token_urlsafe(32)


def make_salt() -> bytes:
    return secrets.token_bytes(16)


def make_nonce() -> str:
    return secrets.token_urlsafe(24)


def derive_key(password: str, salt: bytes, iterations: int = AUTH_ITERATIONS) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )


def make_proof(key: bytes, nonce: str) -> str:
    return hmac.new(key, nonce.encode("utf-8"), hashlib.sha256).hexdigest()


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def read_json_body(handler: Any) -> dict[str, Any]:
    raw_length = handler.headers.get("Content-Length", "0")
    try:
        length = int(raw_length)
    except ValueError as exc:
        raise AgentFTPError(400, "bad_content_length", "Invalid Content-Length") from exc
    if length <= 0:
        return {}
    if length > MAX_JSON_BODY:
        drain_request_body(handler, length, MAX_JSON_BODY + 1)
        raise AgentFTPError(413, "json_too_large", "JSON request body is too large")
    data = handler.rfile.read(length)
    try:
        payload = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise AgentFTPError(400, "bad_json", "Request body must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise AgentFTPError(400, "bad_json", "Request body must be a JSON object")
    return payload


def drain_request_body(handler: Any, length: int, limit: int) -> None:
    remaining = min(max(length, 0), max(limit, 0))
    while remaining:
        chunk = handler.rfile.read(min(64 * 1024, remaining))
        if not chunk:
            break
        remaining -= len(chunk)


def send_json(handler: Any, status: int, payload: dict[str, Any]) -> None:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def send_error(handler: Any, exc: Exception) -> None:
    if isinstance(exc, OSError):
        exc = storage_error(exc)
    if isinstance(exc, AgentFTPError):
        send_json(handler, exc.status, {"error": exc.code, "message": exc.message})
        return
    send_json(handler, 500, {"error": "internal_error", "message": str(exc)})


def console_safe(value: object, stream: Any | None = None) -> str:
    text = str(value)
    target = stream or sys.stdout
    encoding = getattr(target, "encoding", None) or "utf-8"
    try:
        text.encode(encoding)
        return text
    except (LookupError, UnicodeEncodeError):
        return text.encode(encoding, errors="replace").decode(encoding, errors="replace")


def console_print(*values: object, sep: str = " ", end: str = "\n", file: Any | None = None) -> None:
    target = file or sys.stdout
    text = sep.join(console_safe(value, target) for value in values)
    print(text, end=end, file=target)


def storage_error(exc: OSError, action: str = "file operation") -> AgentFTPError:
    code = getattr(exc, "errno", None)
    if code == errno.ENOSPC:
        return AgentFTPError(507, "insufficient_storage", f"{action} failed because disk space is exhausted")
    if code in (errno.EACCES, errno.EPERM):
        return AgentFTPError(403, "permission_denied", f"{action} failed because permission was denied")
    if hasattr(errno, "EROFS") and code == errno.EROFS:
        return AgentFTPError(403, "read_only_filesystem", f"{action} failed because the filesystem is read-only")
    if code == errno.ENAMETOOLONG:
        return AgentFTPError(400, "name_too_long", f"{action} failed because a filename is too long")
    if code == errno.ENOTDIR:
        return AgentFTPError(400, "not_directory", f"{action} failed because a path segment is not a directory")
    if code in (errno.EMFILE, errno.ENFILE):
        return AgentFTPError(503, "file_resource_exhausted", f"{action} failed because file handles are exhausted")
    return AgentFTPError(500, "storage_error", f"{action} failed: {exc}")


def clean_rel_path(path_text: str | None, *, allow_reserved: bool = False) -> str:
    if path_text is None or path_text == "":
        path_text = "/"
    text = str(path_text).replace("\\", "/")
    if "\x00" in text:
        raise AgentFTPError(400, "bad_path", "Path contains a null byte")
    pure = PurePosixPath("/" + text.lstrip("/"))
    parts: list[str] = []
    for part in pure.parts:
        if part in ("", "/", "."):
            continue
        if part == "..":
            raise AgentFTPError(400, "bad_path", "Path traversal is not allowed")
        if ":" in part:
            raise AgentFTPError(400, "bad_path", "Drive-style paths are not allowed")
        part = normalize_wire(part)
        if contains_control(part):
            raise AgentFTPError(400, "bad_path", "Control characters are not allowed in paths")
        if not allow_reserved and part in RESERVED_DIR_NAMES:
            raise AgentFTPError(400, "reserved_path", "agentFTP partial state is reserved")
        parts.append(part)
    return "/" + "/".join(parts)


def join_rel(base: str, *names: str) -> str:
    current = clean_rel_path(base)
    for name in names:
        if not name:
            continue
        current = posixpath.join(current, name.replace("\\", "/"))
    return clean_rel_path(current)


def safe_name(name: str) -> str:
    name = normalize_wire(name)
    if not name or name in (".", ".."):
        raise AgentFTPError(400, "bad_name", "Name is not valid")
    if "/" in name or "\\" in name or "\x00" in name or ":" in name:
        raise AgentFTPError(400, "bad_name", "Name must be a single path segment")
    if contains_control(name):
        raise AgentFTPError(400, "bad_name", "Control characters are not allowed in names")
    if name in RESERVED_DIR_NAMES:
        raise AgentFTPError(400, "reserved_name", "Name is reserved by agentFTP")
    return name


def ensure_inside(root: Path, resolved: Path) -> None:
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise AgentFTPError(403, "path_escape", "Path escapes the configured root") from exc


def resolve_path(root: Path, path_text: str | None, *, allow_missing: bool = False) -> Path:
    root = root.resolve()
    rel = clean_rel_path(path_text)
    parts = [part for part in PurePosixPath(rel).parts if part not in ("", "/")]
    current = root
    for index, part in enumerate(parts):
        matched = match_child_by_normalization(current, part)
        if matched is None:
            if allow_missing:
                rest = [normalize_disk(item) for item in parts[index:]]
                target = current.joinpath(*rest)
                parent = target.parent.resolve()
                ensure_inside(root, parent)
                return target
            raise FileNotFoundError(rel)
        current = matched.resolve()
        ensure_inside(root, current)
    return current


def match_child_by_normalization(parent: Path, segment: str) -> Path | None:
    normalized = normalize_disk(segment)
    exact = parent / normalized
    if exact.exists() or exact.is_symlink():
        return exact
    wire = filename_key(segment)
    matches = []
    try:
        for child in parent.iterdir():
            if filename_key(child.name) == wire:
                matches.append(child)
    except FileNotFoundError:
        return None
    if len(matches) > 1:
        raise AgentFTPError(
            409,
            "ambiguous_filename_normalization",
            "Multiple filenames differ only by Unicode normalization",
        )
    return matches[0] if matches else None


def to_agent_path(root: Path, target: Path) -> str:
    root = root.resolve()
    resolved = target.resolve()
    ensure_inside(root, resolved)
    if resolved == root:
        return "/"
    rel = resolved.relative_to(root)
    return clean_rel_path("/" + rel.as_posix())


def partial_paths(root: Path, target_agent_path: str) -> tuple[Path, Path]:
    clean = clean_rel_path(target_agent_path)
    digest = hashlib.sha256(clean.encode("utf-8")).hexdigest()
    partial_dir = root.resolve() / PARTIAL_DIR_NAME
    partial_dir.mkdir(parents=True, exist_ok=True)
    return partial_dir / f"{digest}.part", partial_dir / f"{digest}.json"


def file_info(root: Path, path: Path) -> dict[str, Any]:
    stat = path.lstat()
    is_symlink = path.is_symlink()
    if is_symlink:
        kind = "symlink"
        size = 0
    elif path.is_dir():
        kind = "dir"
        size = 0
    else:
        kind = "file"
        size = stat.st_size
    return {
        "name": normalize_wire(path.name),
        "path": to_agent_path(root, path),
        "type": kind,
        "size": size,
        "modified": stat.st_mtime,
        "filenameNormalization": filename_policy().__dict__,
    }


def list_dir(root: Path, path_text: str | None) -> dict[str, Any]:
    path = resolve_path(root, path_text)
    if not path.is_dir():
        raise AgentFTPError(400, "not_directory", "Path is not a directory")
    entries = []
    for child in sorted(
        path.iterdir(), key=lambda item: (not item.is_dir(), filename_key(item.name).lower())
    ):
        if child.name in RESERVED_DIR_NAMES:
            continue
        entries.append(file_info(root, child))
    current = to_agent_path(root, path)
    parent = "/" if current == "/" else clean_rel_path(posixpath.dirname(current))
    return {"path": current, "parent": parent, "entries": entries}


def stat_path(root: Path, path_text: str | None) -> dict[str, Any]:
    path = resolve_path(root, path_text)
    return {"exists": True, "entry": file_info(root, path)}


def tree_entries(root: Path, path_text: str | None) -> list[dict[str, Any]]:
    start = resolve_path(root, path_text)
    base = to_agent_path(root, start)
    entries = [file_info(root, start)]
    if start.is_dir():
        for current, dirs, files in os.walk(start, followlinks=False):
            dirs[:] = [name for name in dirs if name not in RESERVED_DIR_NAMES]
            current_path = Path(current)
            for dirname in dirs:
                child = current_path / dirname
                if not child.is_symlink():
                    entries.append(file_info(root, child))
            for filename in files:
                child = current_path / filename
                if child.name not in RESERVED_DIR_NAMES:
                    entries.append(file_info(root, child))
    for entry in entries:
        entry["base"] = base
    return entries


def storage_info(root: Path) -> dict[str, Any]:
    resolved = root.resolve()
    usage = shutil.disk_usage(resolved)
    return {
        "path": str(resolved),
        "totalBytes": usage.total,
        "usedBytes": usage.used,
        "freeBytes": usage.free,
        "freeRatio": usage.free / usage.total if usage.total else 0,
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def detect_addresses(port: int) -> list[tuple[str, str]]:
    addresses: list[tuple[str, str]] = [("Local", f"127.0.0.1:{port}")]
    tailscale = shutil.which("tailscale")
    if tailscale:
        try:
            result = subprocess.run(
                [tailscale, "ip", "-4"],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            for line in result.stdout.splitlines():
                ip = line.strip()
                if ip:
                    addresses.append(("Tailscale", f"{ip}:{port}"))
        except (OSError, subprocess.SubprocessError):
            pass
    for ip in local_ipv4_addresses():
        endpoint = f"{ip}:{port}"
        if endpoint not in {value for _, value in addresses}:
            addresses.append(("LAN", endpoint))
    return addresses


def local_ipv4_addresses() -> list[str]:
    found: list[str] = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            found.append(sock.getsockname()[0])
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127.") and ip not in found:
                found.append(ip)
    except OSError:
        pass
    return found


def format_bytes(value: int) -> str:
    amount = float(value)
    for suffix in ("B", "KB", "MB", "GB", "TB"):
        if amount < 1024 or suffix == "TB":
            if suffix == "B":
                return f"{int(amount)} {suffix}"
            return f"{amount:.1f} {suffix}"
        amount /= 1024


def ensure_storage_available(storage: dict[str, Any], required_bytes: int, destination: str) -> None:
    if required_bytes <= 0:
        return
    free = int(storage.get("freeBytes", 0))
    if required_bytes > free:
        raise AgentFTPError(
            507,
            "insufficient_storage",
            (
                f"{destination} has {format_bytes(free)} free, "
                f"but this transfer needs {format_bytes(required_bytes)}"
            ),
        )
