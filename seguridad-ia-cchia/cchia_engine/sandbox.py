"""Best-effort process containment for CCHIA check workers.

This module deliberately reports capabilities instead of calling the worker a
strong sandbox.  On Windows it attempts to attach the worker to a Job Object;
on POSIX it starts a new session and applies ``setrlimit`` values.  Neither
backend creates a filesystem or network namespace.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable


DEFAULT_MEMORY_MB = 256
DEFAULT_MAX_PROCESSES = 1
DEFAULT_MAX_OUTPUT_BYTES = 1_048_576


@dataclass(frozen=True)
class SandboxLimits:
    """Resource policy applied to one worker process."""

    memory_mb: int
    cpu_seconds: int
    max_processes: int
    max_output_bytes: int

    @classmethod
    def from_execution(cls, execution: dict[str, Any], timeout_seconds: int) -> "SandboxLimits":
        # CPU time is intentionally above the wall timeout so wall-clock
        # termination remains deterministic for sleeping and busy workers.
        return cls(
            memory_mb=_bounded_int(execution.get("memory_limit_mb"), DEFAULT_MEMORY_MB, 32, 4096),
            cpu_seconds=_bounded_int(
                execution.get("cpu_limit_seconds"), max(2, timeout_seconds + 2), 1, 300
            ),
            max_processes=_bounded_int(
                execution.get("max_processes"), DEFAULT_MAX_PROCESSES, 1, 32
            ),
            max_output_bytes=_bounded_int(
                execution.get("max_output_bytes"), DEFAULT_MAX_OUTPUT_BYTES, 4096, 16_777_216
            ),
        )


@dataclass
class SandboxExecution:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    output_limit_exceeded: bool
    report: dict[str, Any]


def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return min(max(value, minimum), maximum)


def minimal_worker_environment(temp_dir: Path) -> tuple[dict[str, str], list[str]]:
    """Return an allowlisted environment without inheriting user credentials."""

    environment = {
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    inherited_names: list[str] = []
    if os.name == "nt":
        for name in ("SystemRoot", "WINDIR"):
            value = os.environ.get(name)
            if value:
                environment[name] = value
                inherited_names.append(name)
        environment["TEMP"] = str(temp_dir)
        environment["TMP"] = str(temp_dir)
    else:
        environment["LANG"] = "C.UTF-8"
        environment["LC_ALL"] = "C.UTF-8"
        environment["TMPDIR"] = str(temp_dir)
    return environment, inherited_names


def _control(
    *, requested: bool, active: bool, mechanism: str | None, detail: str
) -> dict[str, Any]:
    return {
        "requested": requested,
        "active": active,
        "mechanism": mechanism,
        "detail": detail,
    }


def _base_report(limits: SandboxLimits, inherited_names: list[str]) -> dict[str, Any]:
    platform = "windows" if os.name == "nt" else "posix"
    return {
        "profile": "cchia-check-v1",
        "platform": platform,
        "strong_os_boundary": False,
        "controls": {
            "python_isolated_mode": _control(
                requested=True,
                active=True,
                mechanism="python -I -S -B -X utf8",
                detail="Aísla site/user-site y variables PYTHON*; no es una frontera de seguridad OS.",
            ),
            "ast_and_safe_builtins": _control(
                requested=True,
                active=True,
                mechanism="worker AST validation + allowlisted builtins",
                detail="Bloquea imports, I/O directo e introspección conocida en el lenguaje del check.",
            ),
            "temporary_working_directory": _control(
                requested=True,
                active=True,
                mechanism="private TemporaryDirectory",
                detail="El worker se inicia en un directorio efímero eliminado al finalizar.",
            ),
            "minimal_environment": _control(
                requested=True,
                active=True,
                mechanism="explicit allowlist",
                detail=(
                    "No se heredan variables del proceso padre salvo requisitos del cargador OS: "
                    + (", ".join(inherited_names) if inherited_names else "ninguno")
                    + "."
                ),
            ),
            "stdin_closed": _control(
                requested=True,
                active=True,
                mechanism="subprocess.DEVNULL",
                detail="El worker no puede solicitar entrada interactiva.",
            ),
            "wall_timeout": _control(
                requested=True,
                active=True,
                mechanism="parent deadline + tree termination",
                detail="El padre termina el worker y su árbol al superar el plazo.",
            ),
            "process_tree_termination": _control(
                requested=True,
                active=False,
                mechanism=None,
                detail="Se selecciona al iniciar el backend de proceso.",
            ),
            "memory_limit": _control(
                requested=True,
                active=False,
                mechanism=None,
                detail="Pendiente de soporte del backend OS.",
            ),
            "cpu_limit": _control(
                requested=True,
                active=False,
                mechanism=None,
                detail="Pendiente de soporte del backend OS.",
            ),
            "process_limit": _control(
                requested=True,
                active=False,
                mechanism=None,
                detail="Pendiente de soporte del backend OS.",
            ),
            "output_limit": _control(
                requested=True,
                active=True,
                mechanism="bounded pipe readers",
                detail="El padre conserva como máximo la cuota combinada de stdout/stderr y termina el árbol al excederla.",
            ),
            "network_namespace": _control(
                requested=True,
                active=False,
                mechanism=None,
                detail="No disponible en este backend; la API del check no expone imports ni sockets.",
            ),
            "filesystem_read_only_boundary": _control(
                requested=True,
                active=False,
                mechanism=None,
                detail="No hay chroot, mount namespace ni ACL/AppContainer por evaluación.",
            ),
        },
        "limits": {
            "requested": {
                "memory_mb": limits.memory_mb,
                "cpu_seconds": limits.cpu_seconds,
                "max_processes": limits.max_processes,
                "max_output_bytes": limits.max_output_bytes,
            },
            "enforced": {
                "memory_mb": None,
                "cpu_seconds": None,
                "max_processes": None,
                "max_output_bytes": limits.max_output_bytes,
            },
        },
        "fallbacks": [],
        "limitations": [
            "No existe aislamiento OS de red ni una vista read-only del filesystem.",
            "Los checks del catálogo deben seguir siendo revisados y confiables.",
            "El límite de output protege memoria del padre mediante captura acotada; no es una cuota de disco/kernel.",
        ],
    }


def initial_sandbox_report(
    limits: SandboxLimits, inherited_environment_names: list[str]
) -> dict[str, Any]:
    """Build a report for launch failures before a backend can add capabilities."""

    return _base_report(limits, inherited_environment_names)


def _posix_preexec(limits: SandboxLimits) -> Callable[[], None]:
    def apply_limits() -> None:
        import resource

        memory = limits.memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
        # RLIMIT_NPROC counts every process/thread owned by the real UID, not
        # members of this worker's process group.  Applying max_processes as an
        # absolute UID-wide ceiling makes a child fork fail immediately on
        # shared CI/container users that already own more processes than the
        # requested sandbox quota.  A truthful per-tree process quota requires
        # a dedicated UID or a writable cgroup pids controller, neither of
        # which this portable backend can assume.
        if hasattr(resource, "RLIMIT_CORE"):
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    return apply_limits


class _WindowsJob:
    """Small ctypes wrapper; the handle owns every assigned descendant."""

    def __init__(self, limits: SandboxLimits):
        import ctypes
        from ctypes import wintypes

        self._ctypes = ctypes
        self._wintypes = wintypes
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.handle: Any = None
        self.error: str | None = None

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            ]

        class BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        self._kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self._kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        self._kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        self._kernel32.SetInformationJobObject.restype = wintypes.BOOL
        self._kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self._kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        self._kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self._kernel32.TerminateJobObject.restype = wintypes.BOOL
        self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32.CloseHandle.restype = wintypes.BOOL

        handle = self._kernel32.CreateJobObjectW(None, None)
        if not handle:
            self.error = self._last_error("CreateJobObjectW")
            return

        JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000002
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
        JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
        info = EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = (
            JOB_OBJECT_LIMIT_PROCESS_TIME
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        info.BasicLimitInformation.PerProcessUserTimeLimit = limits.cpu_seconds * 10_000_000
        info.BasicLimitInformation.ActiveProcessLimit = limits.max_processes
        info.ProcessMemoryLimit = limits.memory_mb * 1024 * 1024
        if not self._kernel32.SetInformationJobObject(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            self.error = self._last_error("SetInformationJobObject")
            self._kernel32.CloseHandle(handle)
            return
        self.handle = handle

    def _last_error(self, operation: str) -> str:
        code = self._ctypes.get_last_error()
        return f"{operation} failed with WinError {code}: {self._ctypes.FormatError(code).strip()}"

    def assign(self, process: subprocess.Popen[bytes]) -> bool:
        if not self.handle:
            return False
        process_handle = self._wintypes.HANDLE(int(process._handle))  # type: ignore[attr-defined]
        if not self._kernel32.AssignProcessToJobObject(self.handle, process_handle):
            self.error = self._last_error("AssignProcessToJobObject")
            self.close()
            return False
        return True

    def terminate(self, exit_code: int = 124) -> bool:
        return bool(self.handle and self._kernel32.TerminateJobObject(self.handle, exit_code))

    def close(self) -> None:
        if self.handle:
            self._kernel32.CloseHandle(self.handle)
            self.handle = None


def _terminate_posix_tree(process: subprocess.Popen[bytes]) -> tuple[bool, str]:
    try:
        os.killpg(process.pid, signal.SIGKILL)
        return True, "os.killpg(SIGKILL)"
    except ProcessLookupError:
        return True, "process group already exited"
    except OSError as exc:
        try:
            process.kill()
        except OSError:
            pass
        return False, f"killpg failed: {type(exc).__name__}: {exc}"


def _terminate_windows_tree(
    process: subprocess.Popen[bytes], job: _WindowsJob | None
) -> tuple[bool, str]:
    if job and job.handle and job.terminate():
        return True, "TerminateJobObject"
    try:
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        completed = subprocess.run(
            ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
            creationflags=creationflags,
        )
        if completed.returncode == 0:
            return True, "taskkill /T /F fallback"
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        process.kill()
        return False, "Popen.kill fallback (tree termination not proven)"
    except OSError as exc:
        return False, f"termination failed: {type(exc).__name__}: {exc}"


def _bounded_pipe_reader(
    stream: BinaryIO,
    sink: bytearray,
    state: dict[str, int],
    lock: threading.Lock,
    exceeded: threading.Event,
    maximum: int,
) -> None:
    """Drain one pipe while retaining at most ``maximum`` bytes globally."""

    try:
        while True:
            chunk = stream.read(65_536)
            if not chunk:
                return
            with lock:
                remaining = max(0, maximum - state["captured"])
                if remaining:
                    kept = chunk[:remaining]
                    sink.extend(kept)
                    state["captured"] += len(kept)
                if len(chunk) > remaining:
                    exceeded.set()
    except (OSError, ValueError):
        return


def run_worker_process(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    inherited_environment_names: list[str],
    timeout_seconds: int,
    limits: SandboxLimits,
) -> SandboxExecution:
    """Execute one worker and return output plus capability evidence."""

    report = _base_report(limits, inherited_environment_names)
    popen_kwargs: dict[str, Any] = {
        "cwd": str(cwd),
        "env": environment,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
    }
    job: _WindowsJob | None = None
    if os.name == "nt":
        popen_kwargs["creationflags"] = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )
        job = _WindowsJob(limits)
        if job.error:
            report["fallbacks"].append(job.error)
    else:
        popen_kwargs["start_new_session"] = True
        popen_kwargs["preexec_fn"] = _posix_preexec(limits)

    try:
        process = subprocess.Popen(command, **popen_kwargs)
    except (OSError, subprocess.SubprocessError) as exc:
        # A failed POSIX preexec is allowed to fall back to process/session
        # isolation. This behavior is explicit in the evidence.
        if os.name != "nt" and "preexec_fn" in popen_kwargs:
            report["fallbacks"].append(
                f"POSIX rlimits unavailable: {type(exc).__name__}: {exc}"
            )
            popen_kwargs.pop("preexec_fn", None)
            process = subprocess.Popen(command, **popen_kwargs)
        else:
            if job:
                job.close()
            raise

    if os.name == "nt":
        assert job is not None
        if job.assign(process):
            controls = report["controls"]
            controls["process_tree_termination"] = _control(
                requested=True,
                active=True,
                mechanism="Windows Job Object KILL_ON_JOB_CLOSE",
                detail="Descendientes asignados al job terminan al cerrar/terminar el Job Object.",
            )
            for name, key, value in (
                ("memory_limit", "memory_mb", limits.memory_mb),
                ("cpu_limit", "cpu_seconds", limits.cpu_seconds),
                ("process_limit", "max_processes", limits.max_processes),
            ):
                controls[name] = _control(
                    requested=True,
                    active=True,
                    mechanism="Windows Job Object",
                    detail=f"Límite solicitado y aplicado: {value}.",
                )
                report["limits"]["enforced"][key] = value
            report["limitations"].append(
                "Windows asigna el proceso al Job Object inmediatamente después de crearlo; existe una ventana de carrera pequeña antes de la asignación."
            )
        else:
            report["fallbacks"].append(job.error or "Windows Job Object assignment unavailable")
            report["controls"]["process_tree_termination"] = _control(
                requested=True,
                active=True,
                mechanism="new process group + taskkill fallback",
                detail="El timeout intenta taskkill /T /F; la garantía depende de la disponibilidad del OS.",
            )
    else:
        rlimits_active = "preexec_fn" in popen_kwargs
        report["controls"]["process_tree_termination"] = _control(
            requested=True,
            active=True,
            mechanism="new session + os.killpg",
            detail="El worker es líder de una sesión/grupo terminado por SIGKILL al vencer el plazo.",
        )
        for name, key, value, mechanism in (
            ("memory_limit", "memory_mb", limits.memory_mb, "RLIMIT_AS"),
            ("cpu_limit", "cpu_seconds", limits.cpu_seconds, "RLIMIT_CPU"),
        ):
            supported = rlimits_active
            report["controls"][name] = _control(
                requested=True,
                active=supported,
                mechanism=mechanism if supported else None,
                detail=(
                    f"Límite solicitado y aplicado: {value}."
                    if supported
                    else "No se pudo demostrar soporte efectivo en esta plataforma."
                ),
            )
            if supported:
                report["limits"]["enforced"][key] = value
        report["controls"]["process_limit"] = _control(
            requested=True,
            active=False,
            mechanism=None,
            detail=(
                "RLIMIT_NPROC es un límite global del UID, no del árbol del worker; "
                "se omite para no bloquear forks legítimos ni interferir con procesos ajenos. "
                "Una cuota por árbol requiere un UID dedicado o cgroup pids."
            ),
        )
        report["limitations"].append(
            "La semántica efectiva de RLIMIT_AS varía por kernel y contenedor."
        )
        report["limitations"].append(
            "POSIX portable no aplica max_processes: RLIMIT_NPROC es global al UID y no contiene un árbol de procesos."
        )

    timed_out = False
    output_limit_exceeded = False
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    capture_state = {"captured": 0}
    capture_lock = threading.Lock()
    output_exceeded = threading.Event()
    assert process.stdout is not None and process.stderr is not None
    readers = [
        threading.Thread(
            target=_bounded_pipe_reader,
            args=(process.stdout, stdout_buffer, capture_state, capture_lock, output_exceeded, limits.max_output_bytes),
            name="cchia-stdout-reader",
            daemon=True,
        ),
        threading.Thread(
            target=_bounded_pipe_reader,
            args=(process.stderr, stderr_buffer, capture_state, capture_lock, output_exceeded, limits.max_output_bytes),
            name="cchia-stderr-reader",
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()

    deadline = time.monotonic() + timeout_seconds
    termination_record: dict[str, Any] | None = None
    try:
        while process.poll() is None:
            if output_exceeded.is_set():
                output_limit_exceeded = True
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            output_exceeded.wait(min(0.02, remaining))

        if timed_out or output_limit_exceeded:
            if os.name == "nt":
                terminated, mechanism = _terminate_windows_tree(process, job)
            else:
                terminated, mechanism = _terminate_posix_tree(process)
            termination_record = {
                "attempted": True,
                "successful": terminated,
                "mechanism": mechanism,
                "reason": "timeout" if timed_out else "output_limit",
            }
            report["controls"]["process_tree_termination"]["last_termination"] = termination_record
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            report["fallbacks"].append("El worker requirió Popen.kill después de la terminación del árbol.")
    finally:
        # Closing a Windows job with KILL_ON_JOB_CLOSE also removes descendants
        # that outlived a normally exiting worker. On POSIX, clean up any
        # remaining process-group members before closing the read pipes.
        if job:
            job.close()
        elif os.name != "nt" and process.poll() is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
        for reader in readers:
            reader.join(timeout=2)
        try:
            process.stdout.close()
            process.stderr.close()
        except OSError:
            pass

    if output_exceeded.is_set():
        output_limit_exceeded = True
    if output_limit_exceeded:
        report["fallbacks"].append(
            f"Output rechazado al exceder la cuota combinada de {limits.max_output_bytes} bytes."
        )
    stdout = bytes(stdout_buffer).decode("utf-8", errors="replace")
    stderr = bytes(stderr_buffer).decode("utf-8", errors="replace")
    return SandboxExecution(
        returncode=process.returncode if process.returncode is not None else -1,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        output_limit_exceeded=output_limit_exceeded,
        report=report,
    )
