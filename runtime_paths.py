"""
Runtime paths for Project Aegis.

Keeping paths here prevents the daemon, trainer, ML detector, and dashboard
from writing to different folders when the project is installed somewhere
other than ~/project-aegis.
"""

from pathlib import Path

import config


PROJECT_ROOT = Path(__file__).resolve().parent
BASE_DIR = Path(getattr(config, "BASE_DIR", PROJECT_ROOT)).expanduser().resolve()

REPORTS_DIR = BASE_DIR / "reports"
ML_DATA_DIR = BASE_DIR / "ml_data"
MODEL_DIR = ML_DATA_DIR / "model"

INCIDENTS_CSV = REPORTS_DIR / "incidents.csv"
INCIDENTS_TEXT = REPORTS_DIR / "incidents.txt"
BLOCKLIST_PATH = REPORTS_DIR / "blocklist.txt"

SYSTEM_METRICS_CSV = ML_DATA_DIR / "system_metrics.csv"
NORMAL_BEHAVIOR_CSV = ML_DATA_DIR / "normal_behavior.csv"
ANOMALY_SCORES_CSV = ML_DATA_DIR / "anomaly_scores.csv"

MODEL_PATH = MODEL_DIR / "aegis_model.keras"
BEST_MODEL_PATH = MODEL_DIR / "best_model.keras"
SCALER_PATH = MODEL_DIR / "scaler.pkl"
METADATA_PATH = MODEL_DIR / "metadata.json"


def as_str(path):
    return str(path)


def ensure_runtime_dirs():
    import os as _os
    for path in (REPORTS_DIR, ML_DATA_DIR, MODEL_DIR):
        path.mkdir(parents=True, exist_ok=True)
        # Least-privilege: setgid + group 'aegis' so both root daemon and
        # regular dashboard user (who is in the aegis group) can read/write.
        if _os.name == "posix":
            try:
                import grp
                gid = grp.getgrnam("aegis").gr_gid
                _os.chown(str(path), -1, gid)  # keep owner, set group
                _os.chmod(str(path), 0o2775)    # rwxrwsr-x (setgid)
            except (KeyError, OSError):
                pass  # aegis group doesn't exist yet or insufficient perms
