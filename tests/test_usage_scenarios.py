from __future__ import annotations

import io
import hashlib
import json
import os
import tempfile
import threading
import time
import unicodedata
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import agentftp.master as master_module
from agentftp.bootstrap import format_summary, run_bootstrap
from agentftp.cleanup import cleanup_stale_partials
from agentftp.cli import main as cli_main
from agentftp.common import MAX_JSON_BODY, MAX_UPLOAD_CHUNK, AgentFTPError, partial_paths
from agentftp.console import should_relaunch_in_console
from agentftp.connections import get_connection, normalize_alias
from agentftp.firewall import maybe_open_firewall, open_firewall_port
from agentftp.headless import handoff, pull, push, report, tell
from agentftp.inbox import create_instruction, list_instructions, read_instruction
from agentftp.master import AgentFTPMasterServer, MasterState, RemoteClient
from agentftp.security import SecurityConfig
from agentftp.slave import AgentFTPSlaveServer, SlaveState
from agentftp.state import TransferLogger, logs_dir
from agentftp.sync import sync_plan_push, sync_pull, sync_push, write_plan
from agentftp.tls import ensure_self_signed_cert, wrap_server_socket
from agentftp.worker import run_worker_loop
from agentftp.workmem import install_work_mem, is_installed, require_work_mem


class UsageScenarioTests(unittest.TestCase):
    def start_slave(self, root: Path, password: str = "secret") -> AgentFTPSlaveServer:
        state = SlaveState(root, password)
        server = AgentFTPSlaveServer(("127.0.0.1", 0), state)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def start_tls_slave(
        self, root: Path, cert_store: Path, password: str = "secret"
    ) -> tuple[AgentFTPSlaveServer, str]:
        state = SlaveState(root, password)
        tls_files = ensure_self_signed_cert(root, store_dir=cert_store)
        server = AgentFTPSlaveServer(("127.0.0.1", 0), state)
        wrap_server_socket(server, tls_files.cert_file, tls_files.key_file)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, tls_files.fingerprint

    def start_slave_with_model(
        self, root: Path, model_id: str, password: str = "secret"
    ) -> AgentFTPSlaveServer:
        state = SlaveState(root, password, model_id=model_id)
        server = AgentFTPSlaveServer(("127.0.0.1", 0), state)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def start_slave_with_security(
        self, root: Path, config: SecurityConfig, password: str = "secret"
    ) -> AgentFTPSlaveServer:
        state = SlaveState(root, password, security_config=config)
        server = AgentFTPSlaveServer(("127.0.0.1", 0), state)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def test_s01_install_work_mem_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install_work_mem(root)
            install_work_mem(root)
            self.assertTrue(is_installed(root))
            log = (root / "AIMemory" / "work.log").read_text(encoding="utf-8")
            self.assertIn("PROJECT_BOOTSTRAPPED", log)
            self.assertIn("RE_ENGAGED", log)

    def test_s02_slave_lists_root_and_hides_reserved_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "visible.txt").write_text("visible", encoding="utf-8")
            (root / ".agentftp").mkdir()
            (root / ".agentftp_partial").mkdir()
            (root / ".agentftp_inbox").mkdir()
            slave = self.start_slave(root)
            try:
                client = RemoteClient("127.0.0.1", slave.server_address[1], "secret")
                names = {entry["name"] for entry in client.list("/")["entries"]}
                self.assertIn("visible.txt", names)
                self.assertNotIn(".agentftp", names)
                self.assertNotIn(".agentftp_partial", names)
                self.assertNotIn(".agentftp_inbox", names)
            finally:
                slave.shutdown()
                slave.server_close()

    def test_s03_connect_alias_token_reuse_and_disconnect(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "config"
            project = root / "project"
            remote = root / "remote"
            project.mkdir()
            remote.mkdir()
            install_work_mem(project)
            slave = self.start_slave(remote)
            previous_home = os.environ.get("AGENTFTP_HOME")
            previous_cwd = Path.cwd()
            try:
                os.environ["AGENTFTP_HOME"] = str(config)
                os.chdir(project)
                out = io.StringIO()
                with redirect_stdout(out):
                    cli_main(
                        [
                            "connect",
                            "lab",
                            "127.0.0.1",
                            str(slave.server_address[1]),
                            "--password",
                            "secret",
                        ]
                    )
                self.assertIn("connected: ::lab", out.getvalue())
                saved = get_connection("lab")
                self.assertIsNotNone(saved)
                self.assertEqual(saved["name"], "::lab")
                self.assertTrue(saved["token"])
                client = RemoteClient(saved["host"], int(saved["port"]), token=saved["token"])
                self.assertEqual(client.list("/")["path"], "/")
                with redirect_stdout(io.StringIO()):
                    cli_main(["disconnect", "::lab"])
                self.assertIsNone(get_connection("lab"))
            finally:
                os.chdir(previous_cwd)
                if previous_home is None:
                    os.environ.pop("AGENTFTP_HOME", None)
                else:
                    os.environ["AGENTFTP_HOME"] = previous_home
                slave.shutdown()
                slave.server_close()

    def test_s04_master_browser_api_upload_download(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()
            install_work_mem(local)
            (local / "master.txt").write_text("from browser api", encoding="utf-8")
            slave = self.start_slave(remote)
            master = None
            try:
                client = RemoteClient("127.0.0.1", slave.server_address[1], "secret")
                master = AgentFTPMasterServer(("127.0.0.1", 0), MasterState(local, client))
                threading.Thread(target=master.serve_forever, daemon=True).start()
                base = f"http://127.0.0.1:{master.server_address[1]}"
                job = request_json(
                    base,
                    "POST",
                    "/api/jobs/upload",
                    {"paths": ["/master.txt"], "remoteDir": "/", "overwrite": False},
                )
                self.assertEqual(wait_job(base, job["id"])["state"], "done")
                self.assertEqual((remote / "master.txt").read_text(encoding="utf-8"), "from browser api")
                job = request_json(
                    base,
                    "POST",
                    "/api/jobs/download",
                    {"paths": ["/master.txt"], "localDir": "/copy", "overwrite": False},
                )
                self.assertEqual(wait_job(base, job["id"])["state"], "done")
                self.assertEqual((local / "copy" / "master.txt").read_text(encoding="utf-8"), "from browser api")
            finally:
                if master:
                    master.shutdown()
                    master.server_close()
                slave.shutdown()
                slave.server_close()

    def test_s05_headless_push_folder_records_host_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()
            install_work_mem(local)
            project = local / "KKK"
            project.mkdir()
            (project / "a.txt").write_text("alpha", encoding="utf-8")
            slave = self.start_slave(remote)
            previous_cwd = Path.cwd()
            try:
                os.chdir(local)
                push(
                    "127.0.0.1",
                    slave.server_address[1],
                    "secret",
                    Path("KKK"),
                    "/incoming",
                    alias="::lab",
                )
                self.assertEqual((remote / "incoming" / "KKK" / "a.txt").read_text(encoding="utf-8"), "alpha")
                history = local / "AIMemory" / "agentftp_hosts" / "lab.md"
                self.assertIn("PUSH", history.read_text(encoding="utf-8"))
            finally:
                os.chdir(previous_cwd)
                slave.shutdown()
                slave.server_close()

    def test_s06_headless_pull_folder_records_host_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()
            install_work_mem(local)
            result = remote / "result"
            result.mkdir()
            (result / "out.txt").write_text("done", encoding="utf-8")
            slave = self.start_slave(remote)
            try:
                pull(
                    "127.0.0.1",
                    slave.server_address[1],
                    "secret",
                    "/result",
                    local,
                    alias="::lab",
                )
                self.assertEqual((local / "result" / "out.txt").read_text(encoding="utf-8"), "done")
                history = local / "AIMemory" / "agentftp_hosts" / "lab.md"
                self.assertIn("PULL", history.read_text(encoding="utf-8"))
            finally:
                slave.shutdown()
                slave.server_close()

    def test_s07_conflict_aborts_without_overwrite_and_succeeds_with_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()
            install_work_mem(local)
            (local / "file.txt").write_text("first", encoding="utf-8")
            slave = self.start_slave(remote)
            previous_cwd = Path.cwd()
            try:
                os.chdir(local)
                push("127.0.0.1", slave.server_address[1], "secret", Path("file.txt"), "/")
                (local / "file.txt").write_text("second", encoding="utf-8")
                with self.assertRaises(AgentFTPError):
                    push("127.0.0.1", slave.server_address[1], "secret", Path("file.txt"), "/")
                push(
                    "127.0.0.1",
                    slave.server_address[1],
                    "secret",
                    Path("file.txt"),
                    "/",
                    overwrite=True,
                )
                self.assertEqual((remote / "file.txt").read_text(encoding="utf-8"), "second")
            finally:
                os.chdir(previous_cwd)
                slave.shutdown()
                slave.server_close()

    def test_s08_instruction_only_handoff_records_both_sides(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()
            install_work_mem(local)
            install_work_mem(remote)
            slave = self.start_slave(remote)
            try:
                instruction = tell(
                    "127.0.0.1",
                    slave.server_address[1],
                    "secret",
                    "Do ZZZ and report back.",
                    local_root=local,
                    from_name="master-agent",
                    alias="::lab",
                )
                self.assertTrue(instruction["handoffFile"])
                self.assertEqual(len(list((local / "AIMemory").glob("handoff_*.md"))), 1)
                self.assertEqual(len(list((remote / "AIMemory").glob("handoff_*.md"))), 1)
                self.assertIn("HANDOFF_SENT", (local / "AIMemory" / "agentftp_hosts" / "lab.md").read_text(encoding="utf-8"))
            finally:
                slave.shutdown()
                slave.server_close()

    def test_s09_file_plus_instruction_links_remote_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()
            install_work_mem(local)
            install_work_mem(remote)
            (local / "LLL.txt").write_text("payload", encoding="utf-8")
            slave = self.start_slave(remote)
            previous_cwd = Path.cwd()
            try:
                os.chdir(local)
                push(
                    "127.0.0.1",
                    slave.server_address[1],
                    "secret",
                    Path("LLL.txt"),
                    "/incoming",
                    alias="::lab",
                )
                tell(
                    "127.0.0.1",
                    slave.server_address[1],
                    "secret",
                    "Use /incoming/LLL.txt to do ZZZ.",
                    local_root=local,
                    from_name="master-agent",
                    paths=["/incoming/LLL.txt"],
                    alias="::lab",
                )
                self.assertEqual((remote / "incoming" / "LLL.txt").read_text(encoding="utf-8"), "payload")
                instructions = list_instructions(remote)
                self.assertEqual(instructions[0]["paths"], ["/incoming/LLL.txt"])
            finally:
                os.chdir(previous_cwd)
                slave.shutdown()
                slave.server_close()

    def test_s10_full_handoff_report_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            master_root = root / "master"
            worker_root = root / "worker"
            master_root.mkdir()
            worker_root.mkdir()
            install_work_mem(master_root)
            install_work_mem(worker_root)
            worker_slave = self.start_slave(worker_root)
            master_slave = self.start_slave(master_root)
            try:
                instruction = tell(
                    "127.0.0.1",
                    worker_slave.server_address[1],
                    "secret",
                    "Run the worker task.",
                    local_root=master_root,
                    from_name="master-agent",
                    alias="::worker",
                    expect_report="Return pass/fail.",
                )
                parent_id = instruction["handoffId"]
                report(
                    "127.0.0.1",
                    master_slave.server_address[1],
                    "secret",
                    parent_id,
                    "Worker task completed successfully.",
                    local_root=worker_root,
                    from_name="worker-agent",
                    alias="::master",
                )
                master_inbox = list_instructions(master_root)
                self.assertEqual(len(master_inbox), 1)
                self.assertIn("completed successfully", master_inbox[0]["task"])
                master_handoffs = list((master_root / "AIMemory").glob("handoff_*.md"))
                self.assertTrue(any("STATUS_REPORT" in path.read_text(encoding="utf-8") for path in master_handoffs))
            finally:
                worker_slave.shutdown()
                worker_slave.server_close()
                master_slave.shutdown()
                master_slave.server_close()

    def test_s11_remote_file_operations_stay_inside_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            slave = self.start_slave(root)
            try:
                client = RemoteClient("127.0.0.1", slave.server_address[1], "secret")
                client.mkdir("/a")
                client.mkdir("/b")
                (root / "a" / "one.txt").write_text("1", encoding="utf-8")
                client.rename("/a/one.txt", "two.txt")
                self.assertTrue((root / "a" / "two.txt").exists())
                client.move("/a/two.txt", "/b")
                self.assertTrue((root / "b" / "two.txt").exists())
                client.delete("/b/two.txt")
                self.assertFalse((root / "b" / "two.txt").exists())
            finally:
                slave.shutdown()
                slave.server_close()

    def test_s12_security_rejects_traversal_and_reserved_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            slave = self.start_slave(root)
            try:
                client = RemoteClient("127.0.0.1", slave.server_address[1], "secret")
                with self.assertRaises(AgentFTPError):
                    client.list("/../outside")
                with self.assertRaises(AgentFTPError):
                    client.stat("/.agentftp_partial")
                with self.assertRaises(AgentFTPError):
                    client.mkdir({"bad": "path"})  # type: ignore[arg-type]
            finally:
                slave.shutdown()
                slave.server_close()

    def test_s13_missing_work_mem_blocks_runtime_operations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(AgentFTPError):
                require_work_mem(Path(tmp), prompt_install=False)

    def test_s14_slave_model_is_recorded_for_remote_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()
            install_work_mem(local)
            install_work_mem(remote)
            slave = self.start_slave_with_model(remote, "gpt-5.5-remote-worker")
            try:
                client = RemoteClient("127.0.0.1", slave.server_address[1], "secret")
                self.assertEqual(client.executor_model, "gpt-5.5-remote-worker")
                tell(
                    "127.0.0.1",
                    slave.server_address[1],
                    "secret",
                    "Run under the remote worker model.",
                    local_root=local,
                    from_name="master-agent",
                )
                instructions = list_instructions(remote)
                self.assertEqual(instructions[0]["executorModel"], "gpt-5.5-remote-worker")
                remote_handoff = next((remote / "AIMemory").glob("handoff_*.md"))
                self.assertIn("executorModel: `gpt-5.5-remote-worker`", remote_handoff.read_text(encoding="utf-8"))
            finally:
                slave.shutdown()
                slave.server_close()

    def test_s15_security_limits_reject_oversized_json_upload_and_login_flood(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            slave = self.start_slave_with_security(
                root,
                SecurityConfig(login_failures_per_minute=2, login_block_seconds=60),
            )
            try:
                base = f"http://127.0.0.1:{slave.server_address[1]}"
                for _ in range(2):
                    challenge = request_json(base, "GET", "/api/challenge")
                    with self.assertRaises(HTTPError) as caught:
                        request_json(
                            base,
                            "POST",
                            "/api/login",
                            {"nonce": challenge["nonce"], "proof": "bad"},
                        )
                    self.assertEqual(caught.exception.code, 401)
                with self.assertRaises(HTTPError) as blocked:
                    request_json(base, "GET", "/api/challenge")
                self.assertEqual(blocked.exception.code, 429)
            finally:
                slave.shutdown()
                slave.server_close()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            slave = self.start_slave(root)
            try:
                client = RemoteClient("127.0.0.1", slave.server_address[1], "secret")
                base = f"http://127.0.0.1:{slave.server_address[1]}"
                huge_json = b'{"data":"' + (b"x" * MAX_JSON_BODY) + b'"}'
                with self.assertRaises(HTTPError) as too_large_json:
                    raw_request(
                        base + "/api/upload/status",
                        "POST",
                        huge_json,
                        {
                            "Content-Type": "application/json",
                            "Authorization": f"Bearer {client.token}",
                        },
                    )
                self.assertEqual(too_large_json.exception.code, 413)

                query = urlencode(
                    {
                        "path": "/large.bin",
                        "offset": "0",
                        "total": str(MAX_UPLOAD_CHUNK + 1),
                        "overwrite": "true",
                    }
                )
                with self.assertRaises(HTTPError) as too_large_chunk:
                    raw_request(
                        base + "/api/upload/chunk?" + query,
                        "PUT",
                        b"x" * (MAX_UPLOAD_CHUNK + 1),
                        {"Authorization": f"Bearer {client.token}"},
                    )
                self.assertEqual(too_large_chunk.exception.code, 413)
            finally:
                slave.shutdown()
                slave.server_close()

    def test_s16_firewall_skip_and_bad_port_are_safe(self) -> None:
        maybe_open_firewall(7171, "no")
        with self.assertRaises(AgentFTPError):
            open_firewall_port(0)

    def test_s17_bootstrap_installs_work_mem_and_reports_checks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            commands: list[list[str]] = []
            summary = run_bootstrap(
                root,
                install="yes",
                check_network=False,
                runner=lambda command: commands.append(command) or 0,
            )
            self.assertTrue(is_installed(root))
            self.assertIn("agent-work-mem", summary.installed)
            text = format_summary(summary)
            self.assertIn("agentFTP bootstrap", text)
            self.assertIn("python", text)
            self.assertIn("agent-work-mem", text)
            self.assertTrue(any(check.name == "git" for check in summary.checks))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            summary = run_bootstrap(root, install="no", check_network=False)
            self.assertFalse(is_installed(root))
            self.assertFalse(summary.ok)

    def test_s18_unicode_filename_normalization_across_os_styles(self) -> None:
        composed = "카페-한글.txt"
        decomposed = unicodedata.normalize("NFD", composed)
        self.assertNotEqual(composed, decomposed)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            remote = root / "remote"
            local = root / "local"
            received = root / "received"
            remote.mkdir()
            local.mkdir()
            received.mkdir()
            install_work_mem(local)
            (remote / decomposed).write_text("remote nfd", encoding="utf-8")
            slave = self.start_slave(remote)
            try:
                client = RemoteClient("127.0.0.1", slave.server_address[1], "secret")
                listing = client.list("/")
                names = [entry["name"] for entry in listing["entries"]]
                self.assertIn(composed, names)
                self.assertTrue(all(unicodedata.is_normalized("NFC", name) for name in names))
                self.assertTrue(client.stat("/" + composed)["exists"])
                pull(
                    "127.0.0.1",
                    slave.server_address[1],
                    "secret",
                    "/" + composed,
                    received,
                )
                self.assertTrue((received / composed).exists())
                self.assertFalse((received / decomposed).exists())
            finally:
                slave.shutdown()
                slave.server_close()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            remote = root / "remote"
            local = root / "local"
            remote.mkdir()
            local.mkdir()
            install_work_mem(local)
            (local / decomposed).write_text("local nfd", encoding="utf-8")
            slave = self.start_slave(remote)
            previous_cwd = Path.cwd()
            try:
                os.chdir(local)
                push(
                    "127.0.0.1",
                    slave.server_address[1],
                    "secret",
                    Path(decomposed),
                    "/incoming",
                )
                self.assertTrue((remote / "incoming" / composed).exists())
            finally:
                os.chdir(previous_cwd)
                slave.shutdown()
                slave.server_close()

    def test_s19_handoff_command_pushes_file_and_sends_instruction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()
            install_work_mem(local)
            install_work_mem(remote)
            (local / "LLL.txt").write_text("payload", encoding="utf-8")
            slave = self.start_slave(remote)
            previous_cwd = Path.cwd()
            try:
                os.chdir(local)
                result = handoff(
                    "127.0.0.1",
                    slave.server_address[1],
                    "secret",
                    Path("LLL.txt"),
                    "Use the uploaded file to do ZZZ and report back.",
                    remote_dir="/incoming",
                    from_name="master-agent",
                    expect_report="Summarize result and blockers.",
                    alias="::lab",
                )
                self.assertEqual((remote / "incoming" / "LLL.txt").read_text(encoding="utf-8"), "payload")
                self.assertEqual(result["transfer"]["remotePaths"], ["/incoming/LLL.txt"])
                instructions = list_instructions(remote)
                self.assertEqual(instructions[0]["paths"], ["/incoming/LLL.txt"])
                self.assertIn("handoffId", instructions[0])
                self.assertEqual(len(list((local / "AIMemory").glob("handoff_*.md"))), 1)
                self.assertEqual(len(list((remote / "AIMemory").glob("handoff_*.md"))), 1)
                history = (local / "AIMemory" / "agentftp_hosts" / "lab.md").read_text(encoding="utf-8")
                self.assertIn("PUSH", history)
                self.assertIn("HANDOFF_SENT", history)
            finally:
                os.chdir(previous_cwd)
                slave.shutdown()
                slave.server_close()

    def test_s20_https_self_signed_fingerprint_allows_transfer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            cert_store = root / "tls-store"
            config = root / "config"
            local.mkdir()
            remote.mkdir()
            install_work_mem(local)
            (local / "secure.txt").write_text("encrypted transport", encoding="utf-8")
            slave, fingerprint = self.start_tls_slave(remote, cert_store)
            url = f"https://127.0.0.1:{slave.server_address[1]}"
            previous_cwd = Path.cwd()
            previous_home = os.environ.get("AGENTFTP_HOME")
            try:
                with self.assertRaises(AgentFTPError):
                    RemoteClient(url, slave.server_address[1], "secret")
                os.chdir(local)
                os.environ["AGENTFTP_HOME"] = str(config)
                with redirect_stdout(io.StringIO()):
                    cli_main(
                        [
                            "connect",
                            "secure",
                            url,
                            "--password",
                            "secret",
                            "--tls-fingerprint",
                            fingerprint,
                        ]
                    )
                saved = get_connection("secure")
                self.assertEqual(saved["tlsFingerprint"], fingerprint)
                with redirect_stdout(io.StringIO()):
                    cli_main(["push", "secure", "secure.txt", "/secure"])
                self.assertEqual(
                    (remote / "secure" / "secure.txt").read_text(encoding="utf-8"),
                    "encrypted transport",
                )
            finally:
                os.chdir(previous_cwd)
                if previous_home is None:
                    os.environ.pop("AGENTFTP_HOME", None)
                else:
                    os.environ["AGENTFTP_HOME"] = previous_home
                slave.shutdown()
                slave.server_close()

    def test_s21_inbox_claim_marks_instruction_and_records_memory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()
            install_work_mem(local)
            install_work_mem(remote)
            slave = self.start_slave(remote)
            try:
                instruction = tell(
                    "127.0.0.1",
                    slave.server_address[1],
                    "secret",
                    "Claim this handoff.",
                    local_root=local,
                    from_name="master-agent",
                    auto_run=True,
                )
                with redirect_stdout(io.StringIO()):
                    cli_main(["inbox", "--root", str(remote), "--claim", instruction["id"]])
                claimed = read_instruction(remote, instruction["id"])
                self.assertEqual(claimed["state"], "claimed")
                self.assertEqual(claimed["claimedBy"], "agentftp-worker")
                self.assertIn("HANDOFF_CLAIMED", (remote / "AIMemory" / "work.log").read_text(encoding="utf-8"))
            finally:
                slave.shutdown()
                slave.server_close()

    def test_s22_worker_dry_run_claims_autorun_without_executing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()
            install_work_mem(local)
            install_work_mem(remote)
            slave = self.start_slave(remote)
            try:
                instruction = tell(
                    "127.0.0.1",
                    slave.server_address[1],
                    "secret",
                    "Plan only.\nagentftp-run: python -c \"open('should_not_exist.txt','w').write('bad')\"",
                    local_root=local,
                    from_name="master-agent",
                    auto_run=True,
                )
                out = io.StringIO()
                with redirect_stdout(out):
                    cli_main(["worker", "--root", str(remote), "--once"])
                claimed = read_instruction(remote, instruction["id"])
                self.assertEqual(claimed["state"], "claimed")
                self.assertIn("workerPlan", claimed)
                self.assertFalse((remote / "should_not_exist.txt").exists())
                self.assertIn("agentftp-run", out.getvalue())
            finally:
                slave.shutdown()
                slave.server_close()

    def test_s23_worker_executes_explicit_command_and_writes_local_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()
            install_work_mem(local)
            install_work_mem(remote)
            slave = self.start_slave(remote)
            try:
                instruction = tell(
                    "127.0.0.1",
                    slave.server_address[1],
                    "secret",
                    "Create the worker output.\nagentftp-run: python -c \"from pathlib import Path; Path('done.txt').write_text('ok', encoding='utf-8')\"",
                    local_root=local,
                    from_name="master-agent",
                    auto_run=True,
                )
                with redirect_stdout(io.StringIO()):
                    cli_main(["worker", "--root", str(remote), "--once", "--execute", "yes"])
                self.assertEqual((remote / "done.txt").read_text(encoding="utf-8"), "ok")
                completed = read_instruction(remote, instruction["id"])
                self.assertEqual(completed["state"], "completed")
                self.assertEqual(completed["report"]["state"], "local")
                reports = list((remote / "AIMemory").glob("handoff_report-for-*.md"))
                self.assertTrue(any("STATUS_REPORT" in path.read_text(encoding="utf-8") for path in reports))
            finally:
                slave.shutdown()
                slave.server_close()

    def test_s24_worker_sends_report_to_callback_alias(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            master_root = root / "master"
            worker_root = root / "worker"
            config = root / "worker-config"
            master_root.mkdir()
            worker_root.mkdir()
            install_work_mem(master_root)
            install_work_mem(worker_root)
            master_slave = self.start_slave(master_root)
            worker_slave = self.start_slave(worker_root)
            previous_home = os.environ.get("AGENTFTP_HOME")
            previous_cwd = Path.cwd()
            try:
                os.environ["AGENTFTP_HOME"] = str(config)
                os.chdir(worker_root)
                with redirect_stdout(io.StringIO()):
                    cli_main(
                        [
                            "connect",
                            "master",
                            "127.0.0.1",
                            str(master_slave.server_address[1]),
                            "--password",
                            "secret",
                        ]
                    )
                os.chdir(master_root)
                instruction = tell(
                    "127.0.0.1",
                    worker_slave.server_address[1],
                    "secret",
                    "Run callback work.\nagentftp-run: python -c \"from pathlib import Path; Path('callback_done.txt').write_text('ok', encoding='utf-8')\"",
                    local_root=master_root,
                    from_name="master-agent",
                    auto_run=True,
                    callback_alias="master",
                )
                os.chdir(worker_root)
                with redirect_stdout(io.StringIO()):
                    cli_main(["worker", "--root", str(worker_root), "--once", "--execute", "yes"])
                self.assertEqual((worker_root / "callback_done.txt").read_text(encoding="utf-8"), "ok")
                completed = read_instruction(worker_root, instruction["id"])
                self.assertEqual(completed["report"]["state"], "sent")
                master_inbox = list_instructions(master_root)
                self.assertEqual(len(master_inbox), 1)
                self.assertIn("worker finished", master_inbox[0]["task"])
            finally:
                os.chdir(previous_cwd)
                if previous_home is None:
                    os.environ.pop("AGENTFTP_HOME", None)
                else:
                    os.environ["AGENTFTP_HOME"] = previous_home
                master_slave.shutdown()
                master_slave.server_close()
                worker_slave.shutdown()
                worker_slave.server_close()

    def test_s25_transfer_logger_rotates_and_prunes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logger = TransferLogger(root, "push", max_bytes=220, keep=2)
            logger.start(total_files=3, total_bytes=30)
            for index in range(12):
                logger.event("file_completed", source=f"/source-{index}.txt", target=f"/target-{index}.txt", size=10)
            files = list(logs_dir(root).glob("transfer-*.jsonl"))
            self.assertLessEqual(len(files), 2)
            session = json.loads(logger.session_path.read_text(encoding="utf-8"))
            self.assertEqual(session["id"], logger.session_id)
            self.assertIn(".agentftp/logs/", session["log"])

    def test_s26_headless_push_writes_session_log_and_memory_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()
            install_work_mem(local)
            (local / "logged.txt").write_text("logged", encoding="utf-8")
            slave = self.start_slave(remote)
            previous_cwd = Path.cwd()
            try:
                os.chdir(local)
                result = push(
                    "127.0.0.1",
                    slave.server_address[1],
                    "secret",
                    Path("logged.txt"),
                    "/incoming",
                    alias="::lab",
                )
                session = result["session"]
                self.assertEqual(session["status"], "completed")
                self.assertTrue((local / session["sessionFile"]).exists())
                log_text = (local / session["log"]).read_text(encoding="utf-8")
                self.assertIn("session_started", log_text)
                self.assertIn("file_completed", log_text)
                history = (local / "AIMemory" / "agentftp_hosts" / "lab.md").read_text(encoding="utf-8")
                self.assertIn("session", history)
                self.assertIn(".agentftp/logs/", history)
            finally:
                os.chdir(previous_cwd)
                slave.shutdown()
                slave.server_close()

    def test_s27_remote_storage_errors_are_structured_and_logged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()
            install_work_mem(local)
            (local / "denied.txt").write_text("denied", encoding="utf-8")
            blocker = remote / "incoming"
            blocker.write_text("not a directory", encoding="utf-8")
            slave = self.start_slave(remote)
            previous_cwd = Path.cwd()
            try:
                os.chdir(local)
                with self.assertRaises(AgentFTPError) as caught:
                    push(
                        "127.0.0.1",
                        slave.server_address[1],
                        "secret",
                        Path("denied.txt"),
                        "/incoming",
                    )
                self.assertIn(caught.exception.code, {"storage_error", "permission_denied", "not_directory"})
                log_text = "\n".join(path.read_text(encoding="utf-8") for path in logs_dir(local).glob("transfer-*.jsonl"))
                self.assertIn("session_failed", log_text)
            finally:
                os.chdir(previous_cwd)
                slave.shutdown()
                slave.server_close()

    def test_s28_sync_plan_detects_copy_conflict_and_delete_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            project = local / "project"
            remote_project = remote / "project"
            project.mkdir(parents=True)
            remote_project.mkdir(parents=True)
            install_work_mem(local)
            (project / "same.txt").write_text("same", encoding="utf-8")
            (remote_project / "same.txt").write_text("same", encoding="utf-8")
            stamp = time.time() - 30
            os.utime(project / "same.txt", (stamp, stamp))
            os.utime(remote_project / "same.txt", (stamp, stamp))
            (project / "new.txt").write_text("new", encoding="utf-8")
            (project / "changed.txt").write_text("local changed data", encoding="utf-8")
            (remote_project / "changed.txt").write_text("remote", encoding="utf-8")
            (remote_project / "stale.txt").write_text("stale", encoding="utf-8")
            slave = self.start_slave(remote)
            try:
                client = RemoteClient("127.0.0.1", slave.server_address[1], "secret")
                plan = sync_plan_push(local, project, "/project", client)
                write_plan(local, plan)
                self.assertIn("new.txt", {item["rel"] for item in plan["copy"]})
                self.assertIn("changed.txt", {item["rel"] for item in plan["conflicts"]})
                self.assertIn("stale.txt", {item["rel"] for item in plan["deleteCandidates"]})
                self.assertEqual(plan["summary"]["skipped"], 1)
                self.assertTrue((local / plan["planFile"]).exists())
            finally:
                slave.shutdown()
                slave.server_close()

    def test_s29_sync_push_uploads_missing_files_and_records_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            project = local / "project"
            nested = project / "nested"
            nested.mkdir(parents=True)
            remote.mkdir()
            install_work_mem(local)
            (nested / "a.txt").write_text("alpha", encoding="utf-8")
            slave = self.start_slave(remote)
            try:
                with redirect_stdout(io.StringIO()):
                    result = sync_push(
                        "127.0.0.1",
                        slave.server_address[1],
                        "secret",
                        project,
                        "/project",
                        alias="::lab",
                        local_root=local,
                    )
                self.assertEqual((remote / "project" / "nested" / "a.txt").read_text(encoding="utf-8"), "alpha")
                self.assertEqual(result["session"]["status"], "completed")
                self.assertTrue((local / result["session"]["sessionFile"]).exists())
                self.assertTrue((local / result["plan"]["planFile"]).exists())
                history = (local / "AIMemory" / "agentftp_hosts" / "lab.md").read_text(encoding="utf-8")
                self.assertIn("SYNC_PUSH", history)
                self.assertIn(".agentftp/plans/", history)
            finally:
                slave.shutdown()
                slave.server_close()

    def test_s30_sync_push_conflict_requires_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            project = local / "project"
            remote_project = remote / "project"
            project.mkdir(parents=True)
            remote_project.mkdir(parents=True)
            install_work_mem(local)
            (project / "changed.txt").write_text("new content", encoding="utf-8")
            (remote_project / "changed.txt").write_text("old", encoding="utf-8")
            slave = self.start_slave(remote)
            try:
                with self.assertRaises(AgentFTPError) as caught:
                    with redirect_stdout(io.StringIO()):
                        sync_push(
                            "127.0.0.1",
                            slave.server_address[1],
                            "secret",
                            project,
                            "/project",
                            local_root=local,
                        )
                self.assertEqual(caught.exception.code, "conflicts")
                with redirect_stdout(io.StringIO()):
                    sync_push(
                        "127.0.0.1",
                        slave.server_address[1],
                        "secret",
                        project,
                        "/project",
                        local_root=local,
                        overwrite=True,
                    )
                self.assertEqual((remote_project / "changed.txt").read_text(encoding="utf-8"), "new content")
            finally:
                slave.shutdown()
                slave.server_close()

    def test_s31_sync_pull_downloads_missing_files_and_records_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            remote_project = remote / "project"
            remote_project.mkdir(parents=True)
            local.mkdir()
            install_work_mem(local)
            (remote_project / "result.txt").write_text("done", encoding="utf-8")
            slave = self.start_slave(remote)
            try:
                with redirect_stdout(io.StringIO()):
                    result = sync_pull(
                        "127.0.0.1",
                        slave.server_address[1],
                        "secret",
                        "/project",
                        Path("checkout"),
                        alias="::lab",
                        local_root=local,
                    )
                self.assertEqual((local / "checkout" / "result.txt").read_text(encoding="utf-8"), "done")
                self.assertEqual(result["session"]["status"], "completed")
                self.assertTrue((local / result["plan"]["planFile"]).exists())
                history = (local / "AIMemory" / "agentftp_hosts" / "lab.md").read_text(encoding="utf-8")
                self.assertIn("SYNC_PULL", history)
            finally:
                slave.shutdown()
                slave.server_close()

    def test_s32_sync_pull_missing_remote_reports_not_found(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()
            install_work_mem(local)
            slave = self.start_slave(remote)
            try:
                with self.assertRaises(AgentFTPError) as caught:
                    with redirect_stdout(io.StringIO()):
                        sync_pull(
                            "127.0.0.1",
                            slave.server_address[1],
                            "secret",
                            "/missing",
                            Path("checkout"),
                            local_root=local,
                        )
                self.assertEqual(caught.exception.code, "not_found")
            finally:
                slave.shutdown()
                slave.server_close()

    def test_s33_sync_plan_cli_writes_plan_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            project = local / "project"
            project.mkdir(parents=True)
            remote.mkdir()
            install_work_mem(local)
            (project / "cli.txt").write_text("cli", encoding="utf-8")
            slave = self.start_slave(remote)
            previous_cwd = Path.cwd()
            try:
                os.chdir(local)
                out = io.StringIO()
                with redirect_stdout(out):
                    cli_main(
                        [
                            "sync",
                            "plan",
                            "127.0.0.1",
                            "project",
                            "/project",
                            "--port",
                            str(slave.server_address[1]),
                            "--password",
                            "secret",
                        ]
                    )
                plan = json.loads(out.getvalue())
                self.assertEqual(plan["summary"]["copyFiles"], 1)
                self.assertTrue((local / plan["planFile"]).exists())
            finally:
                os.chdir(previous_cwd)
                slave.shutdown()
                slave.server_close()

    def test_s34_gui_storage_api_reports_local_and_remote_free_space(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()
            slave = self.start_slave(remote)
            master = None
            try:
                client = RemoteClient("127.0.0.1", slave.server_address[1], "secret")
                remote_storage = client.storage()
                self.assertGreater(remote_storage["totalBytes"], 0)
                self.assertGreaterEqual(remote_storage["freeBytes"], 0)
                master = AgentFTPMasterServer(("127.0.0.1", 0), MasterState(local, client))
                threading.Thread(target=master.serve_forever, daemon=True).start()
                base = f"http://127.0.0.1:{master.server_address[1]}"
                local_storage = request_json(base, "GET", "/api/local/storage")
                proxied_remote_storage = request_json(base, "GET", "/api/remote/storage")
                for payload in (local_storage, proxied_remote_storage):
                    self.assertGreater(payload["totalBytes"], 0)
                    self.assertGreaterEqual(payload["freeBytes"], 0)
                    self.assertLessEqual(payload["freeBytes"], payload["totalBytes"])
                    self.assertIn("path", payload)
            finally:
                if master:
                    master.shutdown()
                    master.server_close()
                slave.shutdown()
                slave.server_close()

    def test_s35_headless_push_preflight_blocks_insufficient_remote_space(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()
            install_work_mem(local)
            (local / "large.txt").write_text("larger than fake free space", encoding="utf-8")
            slave = self.start_slave(remote)
            previous_cwd = Path.cwd()
            try:
                os.chdir(local)
                with patch.object(
                    RemoteClient,
                    "storage",
                    return_value={"path": str(remote), "totalBytes": 10, "usedBytes": 9, "freeBytes": 1, "freeRatio": 0.1},
                ):
                    with self.assertRaises(AgentFTPError) as caught:
                        with redirect_stdout(io.StringIO()):
                            push(
                                "127.0.0.1",
                                slave.server_address[1],
                                "secret",
                                Path("large.txt"),
                                "/incoming",
                            )
                self.assertEqual(caught.exception.code, "insufficient_storage")
                self.assertFalse((remote / "incoming" / "large.txt").exists())
                log_text = "\n".join(path.read_text(encoding="utf-8") for path in logs_dir(local).glob("transfer-*.jsonl"))
                self.assertIn("session_failed", log_text)
            finally:
                os.chdir(previous_cwd)
                slave.shutdown()
                slave.server_close()

    def test_s36_master_upload_job_preflight_reports_remote_space_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()
            (local / "large.txt").write_text("larger than fake free space", encoding="utf-8")
            slave = self.start_slave(remote)
            master = None
            try:
                client = RemoteClient("127.0.0.1", slave.server_address[1], "secret")
                master = AgentFTPMasterServer(("127.0.0.1", 0), MasterState(local, client))
                threading.Thread(target=master.serve_forever, daemon=True).start()
                base = f"http://127.0.0.1:{master.server_address[1]}"
                with patch.object(
                    RemoteClient,
                    "storage",
                    return_value={"path": str(remote), "totalBytes": 10, "usedBytes": 9, "freeBytes": 1, "freeRatio": 0.1},
                ):
                    job = request_json(
                        base,
                        "POST",
                        "/api/jobs/upload",
                        {"paths": ["/large.txt"], "remoteDir": "/incoming", "overwrite": False},
                    )
                    result = wait_job(base, job["id"])
                self.assertEqual(result["state"], "error")
                self.assertIn("remote destination", result["error"])
                self.assertFalse((remote / "incoming" / "large.txt").exists())
            finally:
                if master:
                    master.shutdown()
                    master.server_close()
                slave.shutdown()
                slave.server_close()

    def test_s37_headless_pull_preflight_blocks_insufficient_local_space(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()
            (remote / "large.txt").write_text("larger than fake free space", encoding="utf-8")
            slave = self.start_slave(remote)
            try:
                with patch(
                    "agentftp.master.storage_info",
                    return_value={"path": str(local), "totalBytes": 10, "usedBytes": 9, "freeBytes": 1, "freeRatio": 0.1},
                ):
                    with self.assertRaises(AgentFTPError) as caught:
                        with redirect_stdout(io.StringIO()):
                            pull(
                                "127.0.0.1",
                                slave.server_address[1],
                                "secret",
                                "/large.txt",
                                local,
                            )
                self.assertEqual(caught.exception.code, "insufficient_storage")
                self.assertFalse((local / "large.txt").exists())
                log_text = "\n".join(path.read_text(encoding="utf-8") for path in logs_dir(local).glob("transfer-*.jsonl"))
                self.assertIn("session_failed", log_text)
            finally:
                slave.shutdown()
                slave.server_close()

    def test_s38_master_download_job_preflight_reports_local_space_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()
            (remote / "large.txt").write_text("larger than fake free space", encoding="utf-8")
            slave = self.start_slave(remote)
            master = None
            try:
                client = RemoteClient("127.0.0.1", slave.server_address[1], "secret")
                master = AgentFTPMasterServer(("127.0.0.1", 0), MasterState(local, client))
                threading.Thread(target=master.serve_forever, daemon=True).start()
                base = f"http://127.0.0.1:{master.server_address[1]}"
                with patch(
                    "agentftp.master.storage_info",
                    return_value={"path": str(local), "totalBytes": 10, "usedBytes": 9, "freeBytes": 1, "freeRatio": 0.1},
                ):
                    job = request_json(
                        base,
                        "POST",
                        "/api/jobs/download",
                        {"paths": ["/large.txt"], "localDir": "/", "overwrite": False},
                    )
                    result = wait_job(base, job["id"])
                self.assertEqual(result["state"], "error")
                self.assertIn("local destination", result["error"])
                self.assertFalse((local / "large.txt").exists())
            finally:
                if master:
                    master.shutdown()
                    master.server_close()
                slave.shutdown()
                slave.server_close()

    def test_s39_master_upload_plan_previews_and_reuses_plan_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()
            (local / "one.txt").write_text("one", encoding="utf-8")
            (local / "two.txt").write_text("two", encoding="utf-8")
            slave = self.start_slave(remote)
            master = None
            try:
                client = RemoteClient("127.0.0.1", slave.server_address[1], "secret")
                master = AgentFTPMasterServer(("127.0.0.1", 0), MasterState(local, client))
                threading.Thread(target=master.serve_forever, daemon=True).start()
                base = f"http://127.0.0.1:{master.server_address[1]}"
                plan = request_json(
                    base,
                    "POST",
                    "/api/plan/upload",
                    {"paths": ["/one.txt", "/two.txt"], "remoteDir": "/incoming"},
                )
                self.assertEqual(plan["direction"], "upload")
                self.assertEqual(plan["totalFiles"], 2)
                self.assertTrue(plan["planId"])
                self.assertTrue(plan["canStart"])
                job = request_json(base, "POST", "/api/jobs/upload", {"planId": plan["planId"], "overwrite": False})
                self.assertEqual(wait_job(base, job["id"])["state"], "done")
                self.assertEqual((remote / "incoming" / "one.txt").read_text(encoding="utf-8"), "one")
                self.assertEqual((remote / "incoming" / "two.txt").read_text(encoding="utf-8"), "two")
            finally:
                if master:
                    master.shutdown()
                    master.server_close()
                slave.shutdown()
                slave.server_close()

    def test_s40_master_download_plan_reports_conflicts_and_space(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()
            (remote / "one.txt").write_text("remote", encoding="utf-8")
            (local / "one.txt").write_text("local", encoding="utf-8")
            slave = self.start_slave(remote)
            master = None
            try:
                client = RemoteClient("127.0.0.1", slave.server_address[1], "secret")
                master = AgentFTPMasterServer(("127.0.0.1", 0), MasterState(local, client))
                threading.Thread(target=master.serve_forever, daemon=True).start()
                base = f"http://127.0.0.1:{master.server_address[1]}"
                plan = request_json(
                    base,
                    "POST",
                    "/api/plan/download",
                    {"paths": ["/one.txt"], "localDir": "/"},
                )
                self.assertEqual(plan["direction"], "download")
                self.assertEqual(plan["conflicts"], ["/one.txt"])
                self.assertIn("freeBytes", plan["destinationStorage"])
                job = request_json(base, "POST", "/api/jobs/download", {"planId": plan["planId"], "overwrite": True})
                self.assertEqual(wait_job(base, job["id"])["state"], "done")
                self.assertEqual((local / "one.txt").read_text(encoding="utf-8"), "remote")
            finally:
                if master:
                    master.shutdown()
                    master.server_close()
                slave.shutdown()
                slave.server_close()

    def test_s41_cli_pull_records_memory_in_current_project_not_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            remote = root / "remote"
            received = project / "received"
            project.mkdir()
            remote.mkdir()
            install_work_mem(project)
            (remote / "result.txt").write_text("result", encoding="utf-8")
            slave = self.start_slave(remote)
            previous_cwd = Path.cwd()
            try:
                os.chdir(project)
                with redirect_stdout(io.StringIO()):
                    cli_main(
                        [
                            "pull",
                            "127.0.0.1",
                            "/result.txt",
                            "received",
                            "--port",
                            str(slave.server_address[1]),
                            "--password",
                            "secret",
                        ]
                    )
                self.assertEqual((received / "result.txt").read_text(encoding="utf-8"), "result")
                self.assertTrue((project / ".agentftp" / "sessions").exists())
                self.assertFalse((received / "AIMemory").exists())
            finally:
                os.chdir(previous_cwd)
                slave.shutdown()
                slave.server_close()

    def test_s42_sync_compare_hash_avoids_same_content_mtime_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            project = local / "project"
            remote_project = remote / "project"
            project.mkdir(parents=True)
            remote_project.mkdir(parents=True)
            install_work_mem(local)
            (project / "same.txt").write_text("same", encoding="utf-8")
            (remote_project / "same.txt").write_text("same", encoding="utf-8")
            os.utime(project / "same.txt", (time.time() - 300, time.time() - 300))
            os.utime(remote_project / "same.txt", (time.time(), time.time()))
            slave = self.start_slave(remote)
            try:
                client = RemoteClient("127.0.0.1", slave.server_address[1], "secret")
                plain = sync_plan_push(local, project, "/project", client)
                self.assertEqual(plain["summary"]["conflicts"], 1)
                hashed = sync_plan_push(local, project, "/project", client, compare_hash=True)
                self.assertEqual(hashed["summary"]["conflicts"], 0)
                self.assertEqual(hashed["summary"]["skipped"], 1)
            finally:
                slave.shutdown()
                slave.server_close()

    def test_s43_sync_push_delete_applies_remote_delete_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            project = local / "project"
            remote_project = remote / "project"
            project.mkdir(parents=True)
            remote_project.mkdir(parents=True)
            install_work_mem(local)
            (project / "keep.txt").write_text("keep", encoding="utf-8")
            (remote_project / "keep.txt").write_text("keep", encoding="utf-8")
            stamp = time.time() - 20
            os.utime(project / "keep.txt", (stamp, stamp))
            os.utime(remote_project / "keep.txt", (stamp, stamp))
            (remote_project / "stale.txt").write_text("stale", encoding="utf-8")
            slave = self.start_slave(remote)
            try:
                with patch("sys.stdin.isatty", return_value=False):
                    with redirect_stdout(io.StringIO()):
                        result = sync_push(
                            "127.0.0.1",
                            slave.server_address[1],
                            "secret",
                            project,
                            "/project",
                            delete=True,
                            local_root=local,
                        )
                self.assertFalse((remote_project / "stale.txt").exists())
                self.assertEqual(result["plan"]["summary"]["deleteCandidates"], 1)
            finally:
                slave.shutdown()
                slave.server_close()

    def test_s44_sync_push_preserves_empty_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            project = local / "project"
            project.mkdir(parents=True)
            (project / "empty").mkdir()
            remote.mkdir()
            install_work_mem(local)
            slave = self.start_slave(remote)
            try:
                with redirect_stdout(io.StringIO()):
                    result = sync_push(
                        "127.0.0.1",
                        slave.server_address[1],
                        "secret",
                        project,
                        "/project",
                        local_root=local,
                    )
                self.assertTrue((remote / "project" / "empty").is_dir())
                self.assertEqual(result["plan"]["summary"]["createDirs"], 1)
            finally:
                slave.shutdown()
                slave.server_close()

    def test_s45_slave_token_scopes_block_ungranted_operations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "keep.txt").write_text("keep", encoding="utf-8")
            slave = self.start_slave(root)
            try:
                client = RemoteClient(
                    "127.0.0.1",
                    slave.server_address[1],
                    "secret",
                    scopes=["read", "handoff"],
                )
                self.assertEqual(sorted(client.scopes), ["handoff", "read"])
                self.assertEqual(client.list("/")["path"], "/")
                with self.assertRaises(AgentFTPError) as caught:
                    client.delete("/keep.txt")
                self.assertEqual(caught.exception.code, "scope_denied")
                self.assertTrue((root / "keep.txt").exists())
            finally:
                slave.shutdown()
                slave.server_close()

    def test_s46_master_jobs_can_be_cancelled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = MasterState(root, object())  # type: ignore[arg-type]
            running = threading.Event()

            def runner(job) -> None:
                running.set()
                while not job.cancel_requested:
                    time.sleep(0.01)
                job.raise_if_cancelled()

            job = state.start_job("slow-transfer", runner)
            self.assertTrue(running.wait(1))
            state.cancel_job(job.id)
            for _ in range(100):
                if job.state == "cancelled":
                    break
                time.sleep(0.02)
            self.assertEqual(job.state, "cancelled")
            self.assertTrue(job.as_dict()["cancelRequested"])

    def test_s47_worker_daemon_loop_processes_and_then_idles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install_work_mem(root)
            create_instruction(root, "Review only.", auto_run=True)
            with redirect_stdout(io.StringIO()):
                result = run_worker_loop(root, interval=0.01, max_iterations=2)
            self.assertEqual(result["state"], "stopped")
            self.assertEqual(result["processed"], 1)
            self.assertEqual(result["idle"], 1)
            self.assertEqual(list_instructions(root)[0]["state"], "claimed")

    def test_s48_cleanup_removes_only_stale_partial_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            partial = root / ".agentftp_partial"
            partial.mkdir()
            old_part = partial / "old.part"
            old_meta = partial / "old.json"
            fresh_part = partial / "fresh.part"
            old_part.write_bytes(b"old")
            old_meta.write_text("{}", encoding="utf-8")
            fresh_part.write_bytes(b"fresh")
            old_time = time.time() - 3 * 3600
            os.utime(old_part, (old_time, old_time))
            os.utime(old_meta, (old_time, old_time))
            result = cleanup_stale_partials(root, older_than_hours=1)
            self.assertEqual(result["removedFiles"], 2)
            self.assertFalse(old_part.exists())
            self.assertFalse(old_meta.exists())
            self.assertTrue(fresh_part.exists())

    def test_s49_upload_finish_is_idempotent_after_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            slave = self.start_slave(root)
            try:
                client = RemoteClient("127.0.0.1", slave.server_address[1], "secret")
                data = b"finished once"
                digest = hashlib.sha256(data).hexdigest()
                response = client.upload_chunk("/done.txt", 0, len(data), data, overwrite=False)
                self.assertEqual(response["received"], len(data))
                client.upload_finish("/done.txt", len(data), time.time(), digest, overwrite=False)
                client.upload_finish("/done.txt", len(data), time.time(), digest, overwrite=False)
                self.assertEqual((root / "done.txt").read_bytes(), data)
            finally:
                slave.shutdown()
                slave.server_close()

    def test_s50_console_relaunch_policy_prefers_visible_console(self) -> None:
        self.assertTrue(
            should_relaunch_in_console(
                "auto",
                stdin_isatty=False,
                stdout_isatty=False,
                is_child=False,
                system="windows",
            )
        )
        self.assertFalse(
            should_relaunch_in_console(
                "auto",
                stdin_isatty=True,
                stdout_isatty=True,
                is_child=False,
                system="windows",
            )
        )
        self.assertFalse(
            should_relaunch_in_console(
                "auto",
                stdin_isatty=False,
                stdout_isatty=False,
                is_child=True,
                system="windows",
            )
        )
        self.assertTrue(
            should_relaunch_in_console(
                "auto",
                stdin_isatty=False,
                stdout_isatty=False,
                is_child=False,
                system="linux",
            )
        )
        self.assertTrue(
            should_relaunch_in_console(
                "yes",
                stdin_isatty=True,
                stdout_isatty=True,
                is_child=False,
                system="linux",
            )
        )
        self.assertFalse(
            should_relaunch_in_console(
                "no",
                stdin_isatty=False,
                stdout_isatty=False,
                is_child=False,
                system="windows",
            )
        )

    def test_s51_master_keeps_ui_server_when_stdin_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install_work_mem(root)
            started = threading.Event()
            stopped = threading.Event()
            wait_labels: list[str] = []

            class FakeServer:
                server_address = ("127.0.0.1", 7180)

                def serve_forever(self) -> None:
                    started.set()
                    stopped.wait(1)

                def shutdown(self) -> None:
                    stopped.set()

                def server_close(self) -> None:
                    pass

            class FakeClient:
                base_url = "http://remote.example"

                def __init__(self, *args, **kwargs) -> None:
                    pass

            def fake_wait_without_stdin(label: str) -> None:
                wait_labels.append(label)
                self.assertTrue(started.wait(1))
                raise KeyboardInterrupt()

            with (
                patch.object(master_module, "RemoteClient", FakeClient),
                patch.object(master_module, "bind_master_server", return_value=FakeServer()),
                patch.object(master_module, "input_available", return_value=False),
                patch.object(
                    master_module,
                    "wait_without_stdin",
                    side_effect=fake_wait_without_stdin,
                ),
                patch.object(master_module.webbrowser, "open"),
            ):
                master_module.run_master(
                    "127.0.0.1",
                    7171,
                    root,
                    token="token",
                    open_browser=True,
                )

            self.assertEqual(wait_labels, ["agentFTP master"])
            self.assertTrue(stopped.is_set())

    def test_s52_gui_remote_mkdir_and_upload_target_folder(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()
            (local / "payload.txt").write_text("payload", encoding="utf-8")
            slave = self.start_slave(remote)
            client = RemoteClient("127.0.0.1", slave.server_address[1], "secret")
            master = AgentFTPMasterServer(("127.0.0.1", 0), MasterState(local, client))
            threading.Thread(target=master.serve_forever, daemon=True).start()
            base = f"http://127.0.0.1:{master.server_address[1]}"
            try:
                request_json(
                    base,
                    "POST",
                    "/api/remote/mkdir",
                    {"parent": "/incoming", "name": "gui-new"},
                )
                self.assertTrue((remote / "incoming" / "gui-new").is_dir())

                plan = request_json(
                    base,
                    "POST",
                    "/api/plan/upload",
                    {"paths": ["/payload.txt"], "remoteDir": "/incoming/gui-new"},
                )
                self.assertEqual(plan["files"][0]["target"], "/incoming/gui-new/payload.txt")

                job = request_json(
                    base,
                    "POST",
                    "/api/jobs/upload",
                    {"planId": plan["planId"], "overwrite": False},
                )
                result = wait_job(base, job["id"])
                self.assertEqual(result["state"], "done")
                self.assertEqual(
                    (remote / "incoming" / "gui-new" / "payload.txt").read_text(
                        encoding="utf-8"
                    ),
                    "payload",
                )
            finally:
                master.shutdown()
                master.server_close()
                slave.shutdown()
                slave.server_close()

    def test_s53_gui_file_management_actions_cover_both_sides(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            local.mkdir()
            remote.mkdir()
            (local / "box").mkdir()
            (remote / "rbox").mkdir()
            slave = self.start_slave(remote)
            client = RemoteClient("127.0.0.1", slave.server_address[1], "secret")
            master = AgentFTPMasterServer(("127.0.0.1", 0), MasterState(local, client))
            threading.Thread(target=master.serve_forever, daemon=True).start()
            base = f"http://127.0.0.1:{master.server_address[1]}"
            try:
                request_json(base, "POST", "/api/local/mkdir", {"parent": "/", "name": "new-local"})
                request_json(
                    base,
                    "POST",
                    "/api/local/rename",
                    {"path": "/new-local", "newName": "renamed-local"},
                )
                request_json(
                    base,
                    "POST",
                    "/api/local/move",
                    {"path": "/renamed-local", "destDir": "/box"},
                )
                self.assertTrue((local / "box" / "renamed-local").is_dir())
                request_json(base, "POST", "/api/local/delete", {"path": "/box/renamed-local"})
                self.assertFalse((local / "box" / "renamed-local").exists())

                request_json(base, "POST", "/api/remote/mkdir", {"parent": "/", "name": "new-remote"})
                request_json(
                    base,
                    "POST",
                    "/api/remote/rename",
                    {"path": "/new-remote", "newName": "renamed-remote"},
                )
                request_json(
                    base,
                    "POST",
                    "/api/remote/move",
                    {"path": "/renamed-remote", "destDir": "/rbox"},
                )
                self.assertTrue((remote / "rbox" / "renamed-remote").is_dir())
                request_json(base, "POST", "/api/remote/delete", {"path": "/rbox/renamed-remote"})
                self.assertFalse((remote / "rbox" / "renamed-remote").exists())

                with self.assertRaises(HTTPError) as local_root_delete:
                    request_json(base, "POST", "/api/local/delete", {"path": "/"})
                self.assertEqual(local_root_delete.exception.code, 400)
                with self.assertRaises(HTTPError) as remote_root_delete:
                    request_json(base, "POST", "/api/remote/delete", {"path": "/"})
                self.assertEqual(remote_root_delete.exception.code, 400)
            finally:
                master.shutdown()
                master.server_close()
                slave.shutdown()
                slave.server_close()

    def test_s54_resumable_push_and_pull_continue_existing_partials(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "local"
            remote = root / "remote"
            received = root / "received"
            local.mkdir()
            remote.mkdir()
            received.mkdir()
            upload_data = b"upload-resume-data" * 64
            download_data = b"download-resume-data" * 64
            (local / "resumable.bin").write_bytes(upload_data)
            (remote / "download.bin").write_bytes(download_data)
            upload_part, _ = partial_paths(remote, "/resume/resumable.bin")
            upload_part.write_bytes(upload_data[:17])
            download_part, _ = partial_paths(received, "/download.bin")
            download_part.write_bytes(download_data[:23])
            slave = self.start_slave(remote)
            try:
                with redirect_stdout(io.StringIO()):
                    push(
                        "127.0.0.1",
                        slave.server_address[1],
                        "secret",
                        local / "resumable.bin",
                        "/resume",
                        local_root=local,
                    )
                self.assertEqual((remote / "resume" / "resumable.bin").read_bytes(), upload_data)
                self.assertFalse(upload_part.exists())

                with redirect_stdout(io.StringIO()):
                    pull(
                        "127.0.0.1",
                        slave.server_address[1],
                        "secret",
                        "/download.bin",
                        received,
                    )
                self.assertEqual((received / "download.bin").read_bytes(), download_data)
                self.assertFalse(download_part.exists())
            finally:
                slave.shutdown()
                slave.server_close()

    def test_s55_cli_alias_push_pull_and_tell_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            remote = root / "remote"
            project.mkdir()
            remote.mkdir()
            install_work_mem(project)
            install_work_mem(remote)
            (project / "cli.txt").write_text("cli payload", encoding="utf-8")
            slave = self.start_slave(remote)
            previous_cwd = Path.cwd()
            try:
                os.chdir(project)
                with redirect_stdout(io.StringIO()):
                    cli_main(
                        [
                            "connect",
                            "lab",
                            "127.0.0.1",
                            str(slave.server_address[1]),
                            "--password",
                            "secret",
                        ]
                    )
                self.assertEqual(get_connection("lab")["name"], "::lab")

                with redirect_stdout(io.StringIO()):
                    cli_main(["push", "lab", "cli.txt", "/cli", "--overwrite"])
                self.assertEqual((remote / "cli" / "cli.txt").read_text(encoding="utf-8"), "cli payload")

                with redirect_stdout(io.StringIO()):
                    cli_main(
                        [
                            "tell",
                            "lab",
                            "Check the CLI transfer.",
                            "--path",
                            "/cli/cli.txt",
                            "--from-name",
                            "cli-master",
                            "--auto-run",
                        ]
                    )
                instructions = list_instructions(remote)
                self.assertEqual(len(instructions), 1)
                self.assertEqual(instructions[0]["from"], "cli-master")
                self.assertTrue(instructions[0]["autoRun"])
                self.assertEqual(instructions[0]["paths"], ["/cli/cli.txt"])

                with redirect_stdout(io.StringIO()):
                    cli_main(["pull", "lab", "/cli/cli.txt", "received", "--overwrite"])
                self.assertEqual(
                    (project / "received" / "cli.txt").read_text(encoding="utf-8"),
                    "cli payload",
                )
            finally:
                os.chdir(previous_cwd)
                slave.shutdown()
                slave.server_close()

    def test_s56_gui_has_persistent_transfer_controls_and_queue_monitor(self) -> None:
        html = (Path(__file__).resolve().parents[1] / "src" / "agentftp" / "web" / "index.html").read_text(
            encoding="utf-8"
        )
        self.assertIn('class="transfer-actions"', html)
        self.assertIn('id="upload"', html)
        self.assertIn('id="download"', html)
        self.assertIn('id="transfer-monitor"', html)
        self.assertIn('id="transfer-queue"', html)
        self.assertIn("function renderTransferMonitor", html)
        self.assertIn("Cannot reach the local agentFTP GUI server", html)
        self.assertNotIn('class="bridge"', html)


def request_json(base: str, method: str, path: str, payload: dict | None = None) -> dict:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = __import__("urllib.request").request.Request(
        base + path,
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with __import__("urllib.request").request.urlopen(request, timeout=60) as response:
        raw = response.read()
    return json.loads(raw.decode("utf-8")) if raw else {}


def raw_request(url: str, method: str, body: bytes, headers: dict[str, str]) -> bytes:
    request = Request(url, data=body, headers=headers, method=method)
    with urlopen(request, timeout=60) as response:
        return response.read()


def wait_job(base: str, job_id: str) -> dict:
    for _ in range(100):
        job = request_json(base, "GET", f"/api/jobs/{job_id}")
        if job["state"] in ("done", "error", "cancelled"):
            return job
        time.sleep(0.1)
    raise AssertionError("job timed out")


if __name__ == "__main__":
    unittest.main()
