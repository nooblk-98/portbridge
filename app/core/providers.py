import json
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class CommandRunner(Protocol):
    def run(self, cmd: list[str], *, check: bool = True, input_data: str | None = None) -> CommandResult: ...


class SubprocessRunner:
    def run(self, cmd: list[str], *, check: bool = True, input_data: str | None = None) -> CommandResult:
        logger.info("exec: %s", " ".join(cmd))
        result = subprocess.run(cmd, input=input_data, capture_output=True, text=True)
        if result.stdout.strip():
            logger.info(result.stdout.strip())
        if result.stderr.strip():
            logger.warning(result.stderr.strip())
        if check and result.returncode != 0:
            raise RuntimeError(f"Command failed: {' '.join(cmd)}\nstdout: {result.stdout}\nstderr: {result.stderr}")
        return CommandResult(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)


class FakeRunner:
    def __init__(self):
        self.commands: list[list[str]] = []
        self.responses: dict[str, CommandResult] = {}

    def run(self, cmd: list[str], *, check: bool = True, input_data: str | None = None) -> CommandResult:
        self.commands.append(cmd)
        key = " ".join(cmd)
        if key in self.responses:
            return self.responses[key]
        return CommandResult(returncode=0, stdout="", stderr="")


class StorageBackend(Protocol):
    def load_json(self, path: str, default: Any = None) -> Any: ...

    def save_json(self, path: str, payload: Any) -> None: ...

    def read_text(self, path: str) -> str | None: ...

    def write_text(self, path: str, content: str) -> None: ...

    def exists(self, path: str) -> bool: ...


class JsonFileStorage:
    def __init__(self, base_dir: str | None = None):
        self.base_dir = Path(base_dir) if base_dir else None

    def _resolve(self, path: str) -> Path:
        p = Path(path)
        if not p.is_absolute() and self.base_dir is not None:
            p = self.base_dir / p
        return p

    def load_json(self, path: str, default: Any = None) -> Any:
        p = self._resolve(path)
        if not p.exists():
            return default
        try:
            return json.loads(p.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return default

    def save_json(self, path: str, payload: Any) -> None:
        p = self._resolve(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload, indent=2))

    def read_text(self, path: str) -> str | None:
        p = self._resolve(path)
        if not p.exists():
            return None
        return p.read_text()

    def write_text(self, path: str, content: str) -> None:
        p = self._resolve(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)

    def exists(self, path: str) -> bool:
        return self._resolve(path).exists()


class InMemoryStorage:
    def __init__(self):
        self._data: dict[str, Any] = {}

    def load_json(self, path: str, default: Any = None) -> Any:
        return self._data.get(path, default)

    def save_json(self, path: str, payload: Any) -> None:
        self._data[path] = payload

    def read_text(self, path: str) -> str | None:
        return self._data.get(path)

    def write_text(self, path: str, content: str) -> None:
        self._data[path] = content

    def exists(self, path: str) -> bool:
        return path in self._data


class ConfigProvider(Protocol):
    @property
    def data_dir(self) -> Path: ...
    @property
    def clients_dir(self) -> Path: ...
    @property
    def clients_file(self) -> Path: ...
    @property
    def forward_file(self) -> Path: ...
    @property
    def wg_config_path(self) -> Path: ...
    @property
    def wg_interface(self) -> str: ...
    @property
    def wg_port(self) -> int: ...
    @property
    def wg_host(self) -> str: ...
    @property
    def app_port(self) -> int: ...
    @property
    def wg_network(self) -> Any: ...
    @property
    def wg_address(self) -> Any: ...
    @property
    def admin_password(self) -> str: ...
    @property
    def default_client_name(self) -> str: ...
    @property
    def default_forward_target(self) -> str: ...
    @property
    def nat_chain(self) -> str: ...
    @property
    def filter_chain(self) -> str: ...
    @property
    def secret_key(self) -> bytes: ...
