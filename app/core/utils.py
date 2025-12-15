
import subprocess
import logging
import json

def run(cmd, check=True, input_data=None):
    logging.info("exec: %s", " ".join(cmd))
    result = subprocess.run(
        cmd,
        input=input_data,
        capture_output=True,
        text=True,
    )
    if result.stdout.strip():
        logging.info(result.stdout.strip())
    if result.stderr.strip():
        logging.warning(result.stderr.strip())
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\nstdout: {result.stdout}\nstderr: {result.stderr}")
    return result

def load_json(path, default):
    try:
        with path.open() as handle:
            return json.load(handle)
    except FileNotFoundError:
        return default
    except json.JSONDecodeError:
        return default

def save_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as handle:
        json.dump(payload, handle, indent=2)
