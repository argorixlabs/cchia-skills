from __future__ import annotations

import ctypes
import json
import os
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch


SKILL_ROOT = Path(__file__).resolve().parents[1]
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from cchia_engine.models import CheckPackage
from cchia_engine.runner import run_check
from cchia_engine import sandbox as sandbox_module
from cchia_engine.sandbox import SandboxLimits, minimal_worker_environment, run_worker_process
from cchia_engine.utils import canonical_hash, sha256_file


VALID_RESULT = """{
    "status": "PASS",
    "confidence": "HIGH",
    "evidence_level": "E1",
    "summary": "ok",
    "evidence": [],
    "recommendation": "none",
}"""


def _context() -> dict:
    return {
        "signals": [],
        "signal_evidence": {},
        "files": [],
        "system": {},
        "collection": {"complete": True},
    }


def _package(root: Path, source: str, **execution_overrides: int) -> CheckPackage:
    package_path = root / "CCHIA-TEST-001"
    package_path.mkdir(parents=True)
    check_path = package_path / "check.py"
    check_path.write_text(source, encoding="utf-8")
    execution = {"mode": "read_only", "timeout_seconds": 2, **execution_overrides}
    return CheckPackage(
        path=package_path,
        control={
            "id": "CCHIA-TEST-001",
            "version": "1.0.0",
            "domain": "TEST",
            "title": "Sandbox adversarial fixture",
            "severity": "MEDIUM",
            "execution": execution,
            "finding": {},
        },
        expected={
            "required_fields": [
                "status",
                "confidence",
                "evidence_level",
                "summary",
                "evidence",
                "recommendation",
            ],
            "allowed_statuses": ["PASS", "FAIL", "PARTIAL", "NOT_ASSESSED", "ERROR"],
        },
        mapping={"frameworks": {}, "sources": []},
        source_hash=sha256_file(check_path),
    )


def _pid_is_alive(pid: int) -> bool:
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    SYNCHRONIZE = 0x00100000
    WAIT_TIMEOUT = 0x00000102
    handle = kernel32.OpenProcess(SYNCHRONIZE, False, pid)
    if not handle:
        return False
    try:
        return kernel32.WaitForSingleObject(handle, 0) == WAIT_TIMEOUT
    finally:
        kernel32.CloseHandle(handle)


class SandboxAdversarialTests(unittest.TestCase):
    def test_infinite_loop_hits_wall_timeout_and_tree_termination(self):
        with tempfile.TemporaryDirectory() as temp:
            package = _package(
                Path(temp),
                "def evaluate(context):\n    while True:\n        pass\n",
                timeout_seconds=1,
            )
            started = time.monotonic()
            result = run_check(package, _context())
            elapsed = time.monotonic() - started

        self.assertLess(elapsed, 6)
        self.assertEqual("ERROR", result["evaluation"]["status"])
        self.assertIn("TimeoutError", result["execution"]["error"])
        sandbox = result["execution"]["sandbox"]
        self.assertTrue(sandbox["outcome"]["timed_out"])
        tree = sandbox["controls"]["process_tree_termination"]
        self.assertTrue(tree["active"])
        self.assertTrue(tree["last_termination"]["successful"])
        self.assertEqual("timeout", tree["last_termination"]["reason"])

    def test_import_io_and_introspection_attempts_are_rejected(self):
        sources = {
            "import": "import os\ndef evaluate(context):\n    return " + VALID_RESULT + "\n",
            "io": "def evaluate(context):\n    open('forbidden.txt', 'w')\n    return " + VALID_RESULT + "\n",
            "introspection": "def evaluate(context):\n    value = context.__class__\n    return " + VALID_RESULT + "\n",
        }
        for label, source in sources.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp:
                result = run_check(_package(Path(temp), source), _context())
                self.assertEqual("ERROR", result["evaluation"]["status"])
                self.assertIn("ValueError", result["execution"]["error"])

    def test_invalid_result_does_not_escape_contract_boundary(self):
        sources = (
            "def evaluate(context):\n    return ['not', 'an', 'object']\n",
            "def evaluate(context):\n    return {'status': 'PASS'}\n",
        )
        for source in sources:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as temp:
                result = run_check(_package(Path(temp), source), _context())
                self.assertEqual("ERROR", result["evaluation"]["status"])
                self.assertTrue(result["execution"].get("error"))

    def test_output_flood_is_bounded_and_rejected(self):
        source = (
            "def evaluate(context):\n"
            "    return {\n"
            "        'status': 'PASS', 'confidence': 'HIGH', 'evidence_level': 'E1',\n"
            "        'summary': 'x' * 300000, 'evidence': [], 'recommendation': 'none'\n"
            "    }\n"
        )
        with tempfile.TemporaryDirectory() as temp:
            result = run_check(
                _package(Path(temp), source, max_output_bytes=16_384),
                _context(),
            )
        sandbox = result["execution"]["sandbox"]
        self.assertEqual("ERROR", result["evaluation"]["status"])
        self.assertTrue(sandbox["outcome"]["output_limit_exceeded"])
        self.assertTrue(sandbox["controls"]["output_limit"]["active"])
        self.assertLess(len(json.dumps(result)), 100_000)

    def test_moderate_memory_pressure_is_contained_when_os_limit_is_active(self):
        source = (
            "def evaluate(context):\n"
            "    pressure = [0] * 20000000\n"
            "    return " + VALID_RESULT + "\n"
        )
        with tempfile.TemporaryDirectory() as temp:
            result = run_check(
                _package(Path(temp), source, memory_limit_mb=48, timeout_seconds=5),
                _context(),
            )
        memory_control = result["execution"]["sandbox"]["controls"]["memory_limit"]
        if not memory_control["active"]:
            self.skipTest("El OS actual no expone un límite de memoria demostrable")
        self.assertEqual("ERROR", result["evaluation"]["status"])
        self.assertEqual(48, result["execution"]["sandbox"]["limits"]["enforced"]["memory_mb"])

    def test_normal_check_reports_minimal_process_guarantees_and_real_limits(self):
        source = "def evaluate(context):\n    return " + VALID_RESULT + "\n"
        with tempfile.TemporaryDirectory() as temp:
            result = run_check(_package(Path(temp), source), _context())
        execution = result["execution"]
        sandbox = execution["sandbox"]
        self.assertEqual("PASS", result["evaluation"]["status"])
        self.assertEqual("layered-best-effort", execution["isolation"])
        self.assertFalse(sandbox["strong_os_boundary"])
        for name in (
            "python_isolated_mode",
            "ast_and_safe_builtins",
            "temporary_working_directory",
            "minimal_environment",
            "stdin_closed",
            "wall_timeout",
            "output_limit",
        ):
            self.assertTrue(sandbox["controls"][name]["active"], name)
        self.assertFalse(sandbox["controls"]["network_namespace"]["active"])
        self.assertFalse(sandbox["controls"]["filesystem_read_only_boundary"]["active"])
        if os.name != "nt":
            process_limit = sandbox["controls"]["process_limit"]
            self.assertFalse(process_limit["active"])
            self.assertIsNone(sandbox["limits"]["enforced"]["max_processes"])
            self.assertIn("global del UID", process_limit["detail"])
        self.assertTrue(sandbox["limitations"])

    def test_posix_preexec_never_applies_uid_wide_nproc_limit(self):
        calls = []
        fake_resource = types.ModuleType("resource")
        fake_resource.RLIMIT_AS = 1
        fake_resource.RLIMIT_CPU = 2
        fake_resource.RLIMIT_NPROC = 3
        fake_resource.RLIMIT_CORE = 4

        def setrlimit(resource_id, limits):
            calls.append((resource_id, limits))

        fake_resource.setrlimit = setrlimit
        limits = SandboxLimits(
            memory_mb=128,
            cpu_seconds=4,
            max_processes=4,
            max_output_bytes=4096,
        )
        with patch.dict(sys.modules, {"resource": fake_resource}):
            sandbox_module._posix_preexec(limits)()

        applied = {resource_id for resource_id, _limits in calls}
        self.assertEqual({fake_resource.RLIMIT_AS, fake_resource.RLIMIT_CPU, fake_resource.RLIMIT_CORE}, applied)
        self.assertNotIn(fake_resource.RLIMIT_NPROC, applied)

    def test_runner_degrades_pass_when_collection_is_incomplete_before_hashing(self):
        source = "def evaluate(context):\n    return " + VALID_RESULT + "\n"
        context = _context()
        context["collection"] = {
            "complete": False,
            "incomplete_reasons": ["max_files_exceeded"],
        }
        with tempfile.TemporaryDirectory() as temp:
            result = run_check(_package(Path(temp), source), context)
        evaluation = result["evaluation"]
        self.assertEqual("NOT_ASSESSED", evaluation["status"])
        self.assertEqual("LOW", evaluation["confidence"])
        self.assertEqual("E0", evaluation["evidence_level"])
        self.assertIn("Cobertura de recolección incompleta", evaluation["summary"])
        payload = {key: value for key, value in result.items() if key != "evidence_sha256"}
        self.assertEqual(canonical_hash(payload), result["evidence_sha256"])

    def test_timeout_kills_a_spawned_descendant_in_same_os_container(self):
        script = (
            "import subprocess,sys,time; "
            "p=subprocess.Popen([sys.executable,'-I','-S','-c','import time; time.sleep(30)']); "
            "print(p.pid,flush=True); time.sleep(30)"
        )
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            environment, inherited = minimal_worker_environment(temp_path)
            execution = run_worker_process(
                [sys.executable, "-I", "-S", "-B", "-X", "utf8", "-c", script],
                cwd=temp_path,
                environment=environment,
                inherited_environment_names=inherited,
                timeout_seconds=1,
                limits=SandboxLimits(
                    memory_mb=128,
                    cpu_seconds=4,
                    max_processes=4,
                    max_output_bytes=4096,
                ),
            )
        self.assertTrue(execution.timed_out)
        self.assertTrue(
            execution.report["controls"]["process_tree_termination"]["last_termination"]["successful"]
        )
        child_pid = int(execution.stdout.strip().splitlines()[0])
        deadline = time.monotonic() + 2
        while _pid_is_alive(child_pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(_pid_is_alive(child_pid), f"descendant {child_pid} survived timeout")


if __name__ == "__main__":
    unittest.main()
