from __future__ import annotations

import sys
from pathlib import Path

from .common import (
    CHUNK_SIZE,
    AgentFTPError,
    clean_rel_path,
    console_print,
    ensure_storage_available,
    format_bytes,
    join_rel,
    partial_paths,
    resolve_path,
    sha256_file,
    storage_info,
    storage_error,
)
from .handoff import create_handoff
from .master import (
    RemoteClient,
    build_download_transfer_plan,
    build_upload_transfer_plan,
    download_required_bytes,
    upload_required_bytes,
)
from .state import TransferLogger
from .workmem import record_host_event


def push(
    host: str,
    port: int,
    password: str | None,
    local_path: Path,
    remote_dir: str,
    *,
    token: str | None = None,
    overwrite: bool = False,
    alias: str = "",
    local_root: Path | None = None,
    tls_fingerprint: str = "",
    tls_insecure: bool = False,
    ca_file: str = "",
) -> dict:
    local_root, source_agent_path = local_scope(local_path, local_root)
    remote = RemoteClient(
        host,
        port,
        password,
        token=token,
        tls_fingerprint=tls_fingerprint,
        tls_insecure=tls_insecure,
        ca_file=ca_file,
    )
    transfer_root = join_rel(remote_dir, resolve_path(local_root, source_agent_path).name or "local-root")
    logger = TransferLogger(local_root, "push", remote=remote.base_url, alias=alias)
    try:
        plan = build_upload_transfer_plan(remote, local_root, [source_agent_path], remote_dir)
        total = int(plan["totalBytes"])
        logger.start(
            total_files=len(plan["files"]),
            total_bytes=total,
            source=source_agent_path,
            remoteDir=clean_rel_path(remote_dir),
            remotePaths=[transfer_root],
            overwrite=overwrite,
            deleteAllowed=False,
        )
        overwrite = resolve_conflicts(list(plan["conflicts"]), overwrite, "remote")
        required_bytes = upload_required_bytes(remote, plan["files"])
        if required_bytes:
            ensure_storage_available(plan["destinationStorage"], required_bytes, "remote destination")
        done = 0
        for directory in plan["dirs"]:
            remote.mkdir(directory)
        for item in plan["files"]:
            source = resolve_path(local_root, item["source"])
            console_print(f"upload {item['source']} -> {item['target']}")
            digest = sha256_file(source)
            status = remote.upload_status(item["target"], item["size"])
            if status.get("exists") and not overwrite:
                raise AgentFTPError(409, "exists", f"Remote file exists: {item['target']}")
            offset = int(status.get("partialSize", 0))
            if offset > item["size"]:
                raise AgentFTPError(409, "bad_partial", f"Remote partial is larger than source: {item['target']}")
            logger.file_started(item["source"], item["target"], item["size"], resume_offset=offset)
            done += offset
            with source.open("rb") as handle:
                handle.seek(offset)
                current_offset = offset
                while current_offset < item["size"]:
                    chunk = handle.read(min(CHUNK_SIZE, item["size"] - current_offset))
                    if not chunk:
                        break
                    response = remote.upload_chunk(
                        item["target"],
                        current_offset,
                        item["size"],
                        chunk,
                        overwrite=overwrite,
                    )
                    current_offset = int(response.get("received", current_offset + len(chunk)))
                    done += len(chunk)
                    print_progress(done, total)
            remote.upload_finish(
                item["target"],
                item["size"],
                item["mtime"],
                digest,
                overwrite=overwrite,
            )
            logger.file_completed(item["source"], item["target"], item["size"])
    except OSError as exc:
        mapped = storage_error(exc, "local upload read")
        logger.fail(mapped)
        raise mapped from exc
    except Exception as exc:
        logger.fail(exc)
        raise
    logger.complete()
    session = logger.summary()
    console_print(f"push complete: {format_bytes(total)}")
    if alias:
        record_host_event(
            local_root,
            alias,
            host=host,
            port=port,
            event_type="PUSH",
            summary=f"Pushed {source_agent_path} to {remote_dir}.",
            extra={
                "bytes": total,
                "remotePaths": [transfer_root],
                "session": session["session"],
                "log": session["log"],
            },
        )
    return {
        "source": source_agent_path,
        "remoteDir": clean_rel_path(remote_dir),
        "remotePaths": [transfer_root],
        "dirs": plan["dirs"],
        "files": plan["files"],
        "totalBytes": total,
        "session": session,
    }


def pull(
    host: str,
    port: int,
    password: str | None,
    remote_path: str,
    local_dir: Path,
    *,
    token: str | None = None,
    overwrite: bool = False,
    alias: str = "",
    memory_root: Path | None = None,
    tls_fingerprint: str = "",
    tls_insecure: bool = False,
    ca_file: str = "",
) -> None:
    local_root = local_dir.resolve()
    local_root.mkdir(parents=True, exist_ok=True)
    event_root = (memory_root or local_root).resolve()
    remote = RemoteClient(
        host,
        port,
        password,
        token=token,
        tls_fingerprint=tls_fingerprint,
        tls_insecure=tls_insecure,
        ca_file=ca_file,
    )
    logger = TransferLogger(event_root, "pull", remote=remote.base_url, alias=alias)
    try:
        plan = build_download_transfer_plan(remote, local_root, [remote_path], "/")
        total = int(plan["totalBytes"])
        logger.start(
            total_files=len(plan["files"]),
            total_bytes=total,
            remotePath=remote_path,
            localDir=str(local_root),
            overwrite=overwrite,
            deleteAllowed=False,
        )
        overwrite = resolve_conflicts(list(plan["conflicts"]), overwrite, "local")
        required_bytes = download_required_bytes(local_root, plan["files"])
        if required_bytes:
            ensure_storage_available(plan["destinationStorage"], required_bytes, "local destination")
        done = 0
        for directory in plan["dirs"]:
            resolve_path(local_root, directory, allow_missing=True).mkdir(parents=True, exist_ok=True)
        for item in plan["files"]:
            target = resolve_path(local_root, item["target"], allow_missing=True)
            console_print(f"download {item['source']} -> {item['target']}")
            if target.exists() and not overwrite:
                raise AgentFTPError(409, "exists", f"Local file exists: {item['target']}")
            part, meta = partial_paths(local_root, item["target"])
            offset = part.stat().st_size if part.exists() else 0
            if offset > item["size"]:
                part.unlink()
                offset = 0
            logger.file_started(item["source"], item["target"], item["size"], resume_offset=offset)
            done += offset
            with part.open("ab") as handle:
                current_offset = offset
                while current_offset < item["size"]:
                    length = min(CHUNK_SIZE, item["size"] - current_offset)
                    chunk = remote.download_chunk(item["source"], current_offset, length)
                    if not chunk:
                        raise AgentFTPError(502, "empty_chunk", "Remote returned an empty chunk")
                    handle.write(chunk)
                    current_offset += len(chunk)
                    done += len(chunk)
                    print_progress(done, total)
            if part.stat().st_size != item["size"]:
                raise AgentFTPError(400, "size_mismatch", f"Downloaded size mismatch: {item['target']}")
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() and not overwrite:
                raise AgentFTPError(409, "exists", f"Local file exists: {item['target']}")
            part.replace(target)
            if meta.exists():
                meta.unlink()
            if item.get("mtime"):
                import os

                os.utime(target, (float(item["mtime"]), float(item["mtime"])))
            logger.file_completed(item["source"], item["target"], item["size"])
    except OSError as exc:
        mapped = storage_error(exc, "local download write")
        logger.fail(mapped)
        raise mapped from exc
    except Exception as exc:
        logger.fail(exc)
        raise
    logger.complete()
    session = logger.summary()
    console_print(f"pull complete: {format_bytes(total)}")
    if alias:
        record_host_event(
            event_root,
            alias,
            host=host,
            port=port,
            event_type="PULL",
            summary=f"Pulled {remote_path} into {local_root}.",
            extra={"bytes": total, "session": session["session"], "log": session["log"]},
        )
    return {"remotePath": remote_path, "localDir": str(local_root), "totalBytes": total, "session": session}


def tell(
    host: str,
    port: int,
    password: str | None,
    task: str,
    *,
    token: str | None = None,
    local_root: Path | None = None,
    from_name: str = "",
    to_name: str = "any-capable",
    alias: str = "",
    paths: list[str] | None = None,
    expect_report: str = "",
    auto_run: bool = False,
    callback_alias: str = "",
    tls_fingerprint: str = "",
    tls_insecure: bool = False,
    ca_file: str = "",
) -> dict:
    root = (local_root or Path.cwd()).resolve()
    handoff = create_handoff(
        root,
        title=task[:60] or "agentFTP handoff",
        task=task,
        from_model=from_name or "agentftp-local",
        to_model=to_name,
        message_type="DECISION_RELAY",
        paths=paths or [],
        expected_report=expect_report,
        auto_run=auto_run,
        direction="local",
        callback_alias=callback_alias,
    )
    remote = RemoteClient(
        host,
        port,
        password,
        token=token,
        tls_fingerprint=tls_fingerprint,
        tls_insecure=tls_insecure,
        ca_file=ca_file,
    )
    response = remote.send_instruction(
        task,
        from_name=from_name,
        paths=paths,
        expect_report=expect_report,
        auto_run=auto_run,
        handoff=handoff,
        callback_alias=callback_alias,
    )
    instruction = response["instruction"]
    console_print(f"instruction sent: {instruction['id']}")
    console_print(f"local handoff: {handoff['file']}")
    if instruction.get("handoffFile"):
        console_print(f"remote handoff: {instruction['handoffFile']}")
    if alias:
        record_host_event(
            root,
            alias,
            host=host,
            port=port,
            event_type="HANDOFF_SENT",
            summary=f"Sent handoff: {task[:100]}",
            handoff_file=handoff["file"],
            extra={"remoteInstruction": instruction["id"]},
        )
    return instruction


def handoff(
    host: str,
    port: int,
    password: str | None,
    local_path: Path,
    task: str,
    *,
    remote_dir: str = "/incoming",
    token: str | None = None,
    overwrite: bool = False,
    local_root: Path | None = None,
    from_name: str = "",
    to_name: str = "any-capable",
    alias: str = "",
    expect_report: str = "",
    auto_run: bool = False,
    callback_alias: str = "",
    tls_fingerprint: str = "",
    tls_insecure: bool = False,
    ca_file: str = "",
) -> dict:
    root = (local_root or Path.cwd()).resolve()
    transfer = push(
        host,
        port,
        password,
        local_path,
        remote_dir,
        token=token,
        overwrite=overwrite,
        alias=alias,
        local_root=root,
        tls_fingerprint=tls_fingerprint,
        tls_insecure=tls_insecure,
        ca_file=ca_file,
    )
    instruction = tell(
        host,
        port,
        password,
        task,
        token=token,
        local_root=root,
        from_name=from_name,
        to_name=to_name,
        alias=alias,
        paths=list(transfer["remotePaths"]),
        expect_report=expect_report,
        auto_run=auto_run,
        callback_alias=callback_alias,
        tls_fingerprint=tls_fingerprint,
        tls_insecure=tls_insecure,
        ca_file=ca_file,
    )
    console_print(f"handoff complete: {', '.join(transfer['remotePaths'])}")
    return {"transfer": transfer, "instruction": instruction}


def report(
    host: str,
    port: int,
    password: str | None,
    parent_id: str,
    report_text: str,
    *,
    token: str | None = None,
    local_root: Path | None = None,
    from_name: str = "",
    to_name: str = "any-capable",
    alias: str = "",
    paths: list[str] | None = None,
    tls_fingerprint: str = "",
    tls_insecure: bool = False,
    ca_file: str = "",
) -> dict:
    root = (local_root or Path.cwd()).resolve()
    handoff = create_handoff(
        root,
        title=f"Report for {parent_id}",
        task=report_text,
        from_model=from_name or "agentftp-local",
        to_model=to_name,
        message_type="STATUS_REPORT",
        paths=paths or [],
        expected_report="no reply needed",
        auto_run=False,
        parent_id=parent_id,
        direction="local",
    )
    remote = RemoteClient(
        host,
        port,
        password,
        token=token,
        tls_fingerprint=tls_fingerprint,
        tls_insecure=tls_insecure,
        ca_file=ca_file,
    )
    response = remote.send_instruction(
        report_text,
        from_name=from_name,
        paths=paths,
        expect_report="no reply needed",
        auto_run=False,
        handoff=handoff,
    )
    instruction = response["instruction"]
    console_print(f"report sent: {instruction['id']}")
    console_print(f"local report handoff: {handoff['file']}")
    if instruction.get("handoffFile"):
        console_print(f"remote report handoff: {instruction['handoffFile']}")
    if alias:
        record_host_event(
            root,
            alias,
            host=host,
            port=port,
            event_type="REPORT_SENT",
            summary=f"Sent report for {parent_id}.",
            handoff_file=handoff["file"],
            extra={"remoteInstruction": instruction["id"]},
        )
    return instruction


def local_scope(path: Path, root: Path | None = None) -> tuple[Path, str]:
    base = (root or Path.cwd()).resolve()
    target = path.resolve() if path.is_absolute() else (base / path).resolve()
    if not target.exists():
        raise AgentFTPError(404, "not_found", f"Local path not found: {path}")
    try:
        rel = target.relative_to(base)
        agent_path = "/" if rel.as_posix() == "." else "/" + rel.as_posix()
        return base, clean_rel_path(agent_path)
    except ValueError:
        return target.parent, clean_rel_path("/" + target.name)


def resolve_conflicts(conflicts: list[str], overwrite: bool, side: str) -> bool:
    if not conflicts:
        return overwrite
    if overwrite:
        return True
    console_print(f"{len(conflicts)} {side} conflict(s):")
    for path in conflicts[:20]:
        console_print(f"- {path}")
    if len(conflicts) > 20:
        console_print(f"- ... and {len(conflicts) - 20} more")
    if not sys.stdin.isatty():
        raise AgentFTPError(409, "conflicts", "Conflicts found; rerun with --overwrite")
    try:
        answer = input("Overwrite these files? [y/N] ").strip().lower()
    except EOFError as exc:
        raise AgentFTPError(409, "conflicts", "Conflicts found; rerun with --overwrite") from exc
    if answer not in ("y", "yes"):
        raise AgentFTPError(409, "conflicts", "Transfer cancelled because of conflicts")
    return True


def print_progress(done: int, total: int) -> None:
    if total <= 0:
        console_print("progress: 0 B")
        return
    pct = min(100.0, (done / total) * 100)
    console_print(f"progress: {format_bytes(done)} / {format_bytes(total)} ({pct:.1f}%)")
